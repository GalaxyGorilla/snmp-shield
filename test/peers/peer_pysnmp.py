#!/usr/bin/env python3
"""pysnmp peer adapter — an independent SNMP stack for conformance tests.

Contract (identical for every adapter, see test/peers/README.md):

    peer.py <verb> --target HOST:PORT [flags]  ->  one JSON object on stdout

Verbs: get, getnext, getbulk, walk, set, trap, inform.

Vendor divergence is the point of having several adapters: this one is
pure Python (pysnmp 7.x), and it must never be "fixed" to match our own
encoder. If it disagrees with net-snmp or node, that is a finding.

Requires the venv created by test/peers/setup.sh (pysnmp + cryptography;
pysnmp refuses AES/DES privacy without cryptography).
"""

import asyncio
import json
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    NotificationType,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    next_cmd,
    send_notification,
    set_cmd,
    walk_cmd,
)

AUTH_PROTOCOLS = {
    "md5": "USM_AUTH_HMAC96_MD5",
    "sha": "USM_AUTH_HMAC96_SHA",
    "sha224": "USM_AUTH_HMAC128_SHA224",
    "sha256": "USM_AUTH_HMAC192_SHA256",
    "sha384": "USM_AUTH_HMAC256_SHA384",
    "sha512": "USM_AUTH_HMAC384_SHA512",
    "none": "USM_AUTH_NONE",
}

PRIV_PROTOCOLS = {
    "des": "USM_PRIV_CBC56_DES",
    "aes": "USM_PRIV_CFB128_AES",
    "aes192": "USM_PRIV_CFB192_AES",
    "aes256": "USM_PRIV_CFB256_AES",
    "aes192blmt": "USM_PRIV_CFB192_AES_BLUMENTHAL",
    "aes256blmt": "USM_PRIV_CFB256_AES_BLUMENTHAL",
    "none": "USM_PRIV_NONE",
}

VALUE_TYPES = {
    "string": "OctetString",
    "octetstring": "OctetString",
    "int": "Integer",
    "integer": "Integer",
    "oid": "ObjectIdentifier",
    "ipaddress": "IpAddress",
    "gauge": "Gauge32",
    "counter32": "Counter32",
    "counter64": "Counter64",
    "timeticks": "TimeTicks",
    "unsigned": "Unsigned32",
}


def fail(kind, message):
    print(json.dumps({"ok": False, "error_kind": kind, "error": message}))
    sys.exit(0)  # the JSON is the result; exit status is not the signal


def parse_args(argv):
    if not argv:
        fail("usage", "missing verb")
    verb = argv[0]
    opts = {
        "verb": verb,
        "version": "2c",
        "level": "",
        "community": "public",
        "user": "",
        "auth": "",
        "priv": "",
        "auth_proto": "sha",
        "priv_proto": "aes",
        "oids": [],
        "varbinds": [],
        "timeout": 3.0,
        "retries": 0,
        "target": "",
        "max_repetitions": 10,
        "enterprise": "",
        "agent_addr": "",
        "generic": 6,
        "specific": 0,
    }
    i = 1
    while i < len(argv):
        key = argv[i]
        if key in ("--oid", "--varbind", "--target", "--version", "--level",
                   "--community", "--user", "--auth", "--priv",
                   "--auth-proto", "--priv-proto", "--timeout", "--retries",
                   "--max-repetitions", "--enterprise", "--agent-addr",
                   "--generic", "--specific"):
            if i + 1 >= len(argv):
                fail("usage", f"{key} needs a value")
            val = argv[i + 1]
            i += 2
            if key == "--oid":
                opts["oids"].append(val)
            elif key == "--varbind":
                opts["varbinds"].append(val)
            elif key == "--timeout":
                opts["timeout"] = float(val)
            elif key == "--retries":
                opts["retries"] = int(val)
            elif key == "--max-repetitions":
                opts["max_repetitions"] = int(val)
            elif key == "--enterprise":
                opts["enterprise"] = val
            elif key == "--agent-addr":
                opts["agent_addr"] = val
            elif key == "--generic":
                opts["generic"] = int(val)
            elif key == "--specific":
                opts["specific"] = int(val)
            elif key == "--version":
                opts["version"] = val
            elif key == "--level":
                opts["level"] = val
            elif key == "--community":
                opts["community"] = val
            elif key == "--user":
                opts["user"] = val
            elif key == "--auth":
                opts["auth"] = val
            elif key == "--priv":
                opts["priv"] = val
            elif key == "--auth-proto":
                opts["auth_proto"] = val
            elif key == "--priv-proto":
                opts["priv_proto"] = val
            elif key == "--target":
                opts["target"] = val
        else:
            fail("usage", f"unknown flag {key}")
    if not opts["target"]:
        fail("usage", "--target is required")
    return opts


def split_target(target):
    host, _, port = target.rpartition(":")
    if not host:
        host, port = target, "161"
    return host, int(port)


def classify_indication(text):
    low = text.lower()
    if "timeout" in low or "no snmp response" in low:
        return "timeout"
    if ("unknown usm user" in low or "unknown user" in low
            or "wrong digest" in low or "authentication" in low):
        return "auth"
    if "decryption" in low:
        return "decrypt"
    if "unsupported security" in low:
        return "security-level"
    if "not in time window" in low:
        return "timeliness"
    if "unknown engine" in low:
        return "engine-discovery"
    return "indication"


def security(opts):
    """Build the auth/transport pair for this request."""
    if opts["version"] == "3":
        level = opts["level"]
        if not level:
            if opts["auth"] and opts["priv"]:
                level = "authpriv"
            elif opts["auth"]:
                level = "authnopriv"
            else:
                level = "noauthnopriv"
        auth_name = AUTH_PROTOCOLS.get(opts["auth_proto"].lower())
        priv_name = PRIV_PROTOCOLS.get(opts["priv_proto"].lower())
        if auth_name is None:
            fail("usage", f"unknown auth protocol {opts['auth_proto']}")
        if priv_name is None:
            fail("usage", f"unknown priv protocol {opts['priv_proto']}")
        import pysnmp.hlapi.v3arch.asyncio as h

        auth_proto = getattr(h, auth_name)
        priv_proto = getattr(h, priv_name)
        if level == "noauthnopriv":
            user = UsmUserData(opts["user"])
        elif level == "authnopriv":
            user = UsmUserData(opts["user"], opts["auth"], authProtocol=auth_proto)
        else:
            user = UsmUserData(opts["user"], opts["auth"], opts["priv"],
                               authProtocol=auth_proto, privProtocol=priv_proto)
        return user, None
    mp_model = 0 if opts["version"] == "1" else 1
    return CommunityData(opts["community"], mpModel=mp_model), None


def varbind_value(spec):
    """Parse 'oid=TYPE:VALUE' into an ObjectType."""
    oid, _, rest = spec.partition("=")
    type_name, _, value = rest.partition(":")
    cls_name = VALUE_TYPES.get(type_name.lower())
    if cls_name is None:
        fail("usage", f"unknown varbind type {type_name!r} in {spec!r}")
    import pysnmp.hlapi.v3arch.asyncio as h

    cls = getattr(h, cls_name)
    if cls_name == "ObjectIdentifier":
        pdu_value = cls(value)
    elif cls_name in ("Integer", "Gauge32", "Counter32", "Counter64",
                      "TimeTicks", "Unsigned32"):
        pdu_value = cls(int(value))
    else:
        pdu_value = cls(value)
    return ObjectType(ObjectIdentity(oid), pdu_value)


# pysnmp reports the MIB textual convention (DisplayString) or a concrete
# class (Integer32); the contract asks for the base SMI type. Normalizing
# here keeps vendor naming differences out of the assertions.
TYPE_ALIASES = {
    "DisplayString": "OctetString",
    "ObjectIdentifier": "OID",
    "ObjectIdentity": "OID",
    "Integer32": "Integer",
    "IpAddress": "IpAddress",
}


def dump(varbinds):
    out = []
    for name, val in varbinds:
        cls = type(val).__name__
        out.append({
            "oid": str(name),
            "type": TYPE_ALIASES.get(cls, cls),
            "value": val.prettyPrint(),
        })
    return out


async def run(opts):
    host, port = split_target(opts["target"])
    engine = SnmpEngine()
    auth, _ = security(opts)
    target = await UdpTransportTarget.create(
        (host, port), timeout=opts["timeout"], retries=opts["retries"])
    ctx = ContextData()

    if opts["verb"] in ("trap", "inform"):
        if not opts["oids"] and not opts["varbinds"]:
            fail("usage", "trap needs --oid")
        notification = NotificationType(
            ObjectIdentity(opts["oids"][0] if opts["oids"] else ".1.3.6.1.6.3.1.1.5.1"))
        extra = [varbind_value(v) for v in opts["varbinds"]]
        if extra:
            notification = notification.add_varbinds(*extra)
        ei, es, _eidx, _vbs = await send_notification(
            engine, auth, target, ctx,
            "inform" if opts["verb"] == "inform" else "trap", notification)
        if ei:
            fail(classify_indication(str(ei)), str(ei))
        if es:
            fail("status", str(es))
        print(json.dumps({"ok": True, "varbinds": []}))
        return

    if opts["verb"] != "set":
        objects = [ObjectType(ObjectIdentity(o)) for o in opts["oids"]]
        if not objects:
            fail("usage", "at least one --oid is required")

    if opts["verb"] == "get":
        ei, es, eidx, vbs = await get_cmd(engine, auth, target, ctx, *objects)
    elif opts["verb"] == "getnext":
        ei, es, eidx, vbs = await next_cmd(engine, auth, target, ctx, *objects)
    elif opts["verb"] == "walk":
        # walk_cmd is an async generator (one row per iteration), not an
        # awaitable; awaiting it is the classic pysnmp 7 migration error.
        #
        # lexicographicMode=False makes the walk STOP when it leaves the
        # requested subtree. pysnmp defaults it to True, which walks the
        # entire MIB — every other stack's walk (`snmpbulkwalk`, node's
        # `session.subtree`, gosnmp's `BulkWalkAll`) honours the subtree
        # boundary, so leaving the default in place made this adapter the
        # only one that returned hundreds of thousands of varbinds for
        # `walk 1.3.6.1.2.1.1`. That is adapter presentation, not vendor
        # behaviour: it must not look like a peer disagreement.
        rows = []
        async for ei, es, eidx, vbs in walk_cmd(
                engine, auth, target, ctx, *objects[0:1], lexicographicMode=False):
            if ei:
                fail(classify_indication(str(ei)), str(ei))
            if es:
                fail("status", str(es))
            rows.extend(vbs)
        print(json.dumps({"ok": True, "varbinds": dump(rows)}))
        return
    elif opts["verb"] == "getbulk":
        ei, es, eidx, vbs = await bulk_cmd(
            engine, auth, target, ctx, 0, opts["max_repetitions"], *objects)
    elif opts["verb"] == "set":
        if not opts["varbinds"]:
            fail("usage", "set needs --varbind oid=TYPE:value")
        ei, es, eidx, vbs = await set_cmd(
            engine, auth, target, ctx,
            *[varbind_value(v) for v in opts["varbinds"]])
    else:
        fail("usage", f"unknown verb {opts['verb']}")

    if ei:
        fail(classify_indication(str(ei)), str(ei))
    if es:
        print(json.dumps({
            "ok": False,
            "error_kind": "status",
            "error": str(es),
            "error_index": int(eidx),
            "varbinds": dump(vbs),
        }))
        return
    print(json.dumps({"ok": True, "varbinds": dump(vbs)}))


def main():
    opts = parse_args(sys.argv[1:])
    try:
        asyncio.run(run(opts))
    except SystemExit:
        raise
    except Exception as exc:  # a vendor exception is a result, not a crash
        fail("exception", f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
