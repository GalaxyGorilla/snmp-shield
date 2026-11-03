#!/usr/bin/env python3
"""pysnmp v3 agent — an independent SNMPv3 agent for conformance tests.

Why this exists: the v3 agent leg was judged only by net-snmp (the host's
5.6 build and the 5.9 container). Both are the same implementation, so a
bug in how we perform RFC 3414 discovery, localize keys to somebody else's
engine, sign/encrypt, or parse their answer could survive both. This agent
uses pysnmp's USM engine and BER codec, a completely separate stack.

It is a fixture, not a service: it binds one loopback UDP port, answers a
small read-only system-group MIB, refuses SET with notWritable, and exits
when its process is killed. The Go harness waits for a direct v3 GET before
it starts the proxy, so a broken fixture is never blamed on the code under
test.

Usage:
    v3_agent.py --endpoint 127.0.0.1:1161 \
        --user authPrivUser --auth-key authpass --auth-proto SHA \
        --priv-key privpass --priv-proto AES

The context name is deliberately the default (empty): that is what a
standard SNMPv3 manager sends and what the usm-manager-gateway emits.
"""

import argparse
import asyncio
import sys

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.api import v2c

AUTH_PROTOCOLS = {
    "MD5": config.USM_AUTH_HMAC96_MD5,
    "SHA": config.USM_AUTH_HMAC96_SHA,
    "SHA224": config.USM_AUTH_HMAC128_SHA224,
    "SHA256": config.USM_AUTH_HMAC192_SHA256,
    "SHA384": config.USM_AUTH_HMAC256_SHA384,
    "SHA512": config.USM_AUTH_HMAC384_SHA512,
}

PRIV_PROTOCOLS = {
    "DES": config.USM_PRIV_CBC56_DES,
    "3DES": config.USM_PRIV_CBC168_3DES,
    "AES": config.USM_PRIV_CFB128_AES,
    "AES128": config.USM_PRIV_CFB128_AES,
    "AES192": config.USM_PRIV_CFB192_AES,
    "AES256": config.USM_PRIV_CFB256_AES,
}

# A read-only system group. Values are ordinary pysnmp syntax objects so
# the wire encoding is the library's, not ours.
OIDS = {
    (1, 3, 6, 1, 2, 1, 1, 1, 0): rfc1902.OctetString("pysnmp v3 agent"),
    (1, 3, 6, 1, 2, 1, 1, 2, 0): rfc1902.ObjectIdentifier(
        (1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)
    ),
    (1, 3, 6, 1, 2, 1, 1, 3, 0): rfc1902.TimeTicks(12345),
    (1, 3, 6, 1, 2, 1, 1, 4, 0): rfc1902.OctetString("admin@example.com"),
    (1, 3, 6, 1, 2, 1, 1, 5, 0): rfc1902.OctetString("pysnmp"),
    (1, 3, 6, 1, 2, 1, 1, 6, 0): rfc1902.OctetString("here"),
    (1, 3, 6, 1, 2, 1, 1, 7, 0): rfc1902.Integer(72),
}
SORTED = sorted(OIDS)


class GetResponder(cmdrsp.GetCommandResponder):
    def handle_management_operation(self, snmpEngine, stateReference, contextName, PDU):
        out = []
        for oid, _ in v2c.apiPDU.get_varbinds(PDU):
            key = tuple(oid)
            out.append(
                (
                    rfc1902.ObjectIdentifier(key),
                    OIDS.get(key, rfc1905.NoSuchInstance()),
                )
            )
        self.send_varbinds(snmpEngine, stateReference, 0, 0, out)


class NextResponder(cmdrsp.NextCommandResponder):
    def handle_management_operation(self, snmpEngine, stateReference, contextName, PDU):
        out = []
        for oid, _ in v2c.apiPDU.get_varbinds(PDU):
            key = tuple(oid)
            nxt = next((candidate for candidate in SORTED if candidate > key), None)
            if nxt is None:
                out.append((rfc1902.ObjectIdentifier(key), rfc1905.EndOfMibView()))
            else:
                out.append((rfc1902.ObjectIdentifier(nxt), OIDS[nxt]))
        self.send_varbinds(snmpEngine, stateReference, 0, 0, out)


class BulkResponder(cmdrsp.BulkCommandResponder):
    def handle_management_operation(self, snmpEngine, stateReference, contextName, PDU):
        out = []
        reps = v2c.apiBulkPDU.get_max_repetitions(PDU)
        for oid, _ in v2c.apiBulkPDU.get_varbinds(PDU):
            current = tuple(oid)
            for _ in range(max(1, reps)):
                nxt = next(
                    (candidate for candidate in SORTED if candidate > current), None
                )
                if nxt is None:
                    out.append(
                        (rfc1902.ObjectIdentifier(current), rfc1905.EndOfMibView())
                    )
                    break
                out.append((rfc1902.ObjectIdentifier(nxt), OIDS[nxt]))
                current = nxt
        self.send_varbinds(snmpEngine, stateReference, 0, 0, out)


class SetResponder(cmdrsp.SetCommandResponder):
    def handle_management_operation(self, snmpEngine, stateReference, contextName, PDU):
        # Read-only fixture: the refusal must travel back as a PDU error
        # status, not a timeout. The conformance scenario asserts exactly
        # that distinction.
        self.send_varbinds(
            snmpEngine, stateReference, "notWritable", 1, v2c.apiPDU.get_varbinds(PDU)
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--auth-key", required=True)
    parser.add_argument("--auth-proto", default="SHA")
    parser.add_argument("--priv-key", required=True)
    parser.add_argument("--priv-proto", default="AES")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        from pysnmp import debug as pysnmp_debug

        pysnmp_debug.set_logger(pysnmp_debug.Debug("all"))

    host, _, port = args.endpoint.rpartition(":")
    auth = args.auth_proto.upper()
    priv = args.priv_proto.upper()
    if auth not in AUTH_PROTOCOLS:
        parser.error("unsupported auth protocol %q" % args.auth_proto)
    if priv not in PRIV_PROTOCOLS:
        parser.error("unsupported priv protocol %q" % args.priv_proto)

    # pysnmp's asyncio carrier wants an event loop at construction time.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    snmpEngine = engine.SnmpEngine()
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode((host, int(port))),
    )
    config.add_v3_user(
        snmpEngine,
        args.user,
        AUTH_PROTOCOLS[auth],
        args.auth_key,
        PRIV_PROTOCOLS[priv],
        args.priv_key,
    )
    # Read-only VACM: the whole tree is readable, nothing is writable.
    config.add_vacm_user(snmpEngine, 3, args.user, "authPriv", (1, 3, 6), ())

    snmpContext = context.SnmpContext(snmpEngine)
    GetResponder(snmpEngine, snmpContext)
    NextResponder(snmpEngine, snmpContext)
    BulkResponder(snmpEngine, snmpContext)
    SetResponder(snmpEngine, snmpContext)

    snmpEngine.transport_dispatcher.job_started(1)
    snmpEngine.transport_dispatcher.run_dispatcher()
    return 0


if __name__ == "__main__":
    sys.exit(main())
