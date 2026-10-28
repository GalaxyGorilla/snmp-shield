#!/usr/bin/env python3
"""net-snmp CLI peer adapter — wraps the host's net-snmp binaries.

Same CLI/JSON contract as the pysnmp and node adapters (see
test/peers/README.md). This is the reference implementation most operators
actually use, so when it disagrees with the others, it is usually the one
whose behaviour matters.

Two vendor quirks this adapter exists to isolate:
  * GETBULK does not exist in SNMPv1, so `walk` falls back to snmpwalk for
    a v1 peer instead of failing (RFC 2576 4.1.1 the proxy does the same
    downgrade).
  * net-snmp's output/error text is its own; the adapter maps it to the
    contract's `error_kind` so tests never assert on vendor prose.
"""

import json
import os
import re
import shutil
import subprocess
import sys

VERBS = {"get", "getnext", "getbulk", "walk", "set", "trap", "inform"}

SET_TYPES = {
    "string": "s", "octetstring": "s", "int": "i", "integer": "i",
    "oid": "o", "ipaddress": "a", "gauge": "u", "unsigned": "u",
    "counter32": "c", "counter64": "C", "timeticks": "t",
}


def fail(kind, message):
    print(json.dumps({"ok": False, "error_kind": kind, "error": message}))
    sys.exit(0)


def parse_args(argv):
    if not argv:
        fail("usage", "missing verb")
    opts = {
        "verb": argv[0], "version": "2c", "level": "", "community": "public",
        "user": "", "auth": "", "priv": "", "auth_proto": "SHA",
        "priv_proto": "AES", "oids": [], "varbinds": [], "timeout": "3",
        "retries": "0", "target": "", "enterprise": "", "agent_addr": "",
        "generic": "6", "specific": "0",
    }
    if opts["verb"] not in VERBS:
        fail("usage", f"unknown verb {opts['verb']}")
    i = 1
    while i < len(argv):
        key = argv[i]
        if i + 1 >= len(argv):
            fail("usage", f"{key} needs a value")
        val = argv[i + 1]
        i += 2
        if key == "--oid":
            opts["oids"].append(val)
        elif key == "--varbind":
            opts["varbinds"].append(val)
        elif key.startswith("--"):
            opts[key[2:].replace("-", "_")] = val
        else:
            fail("usage", f"unknown flag {key}")
    if not opts["target"]:
        fail("usage", "--target is required")
    return opts


def security_flags(opts):
    version = opts["version"]
    if version == "1":
        return ["-v", "1", "-c", opts["community"]]
    if version in ("2", "2c"):
        return ["-v", "2c", "-c", opts["community"]]
    level = (opts["level"] or ("authPriv" if opts["auth"] and opts["priv"]
                               else "authNoPriv" if opts["auth"] else "noAuthNoPriv"))
    level = {"noauthnopriv": "noAuthNoPriv", "authnopriv": "authNoPriv",
             "authpriv": "authPriv"}.get(level.lower(), level)
    flags = ["-v", "3", "-l", level, "-u", opts["user"]]
    if level != "noAuthNoPriv":
        flags += ["-a", opts["auth_proto"].upper(), "-A", opts["auth"]]
    if level == "authPriv":
        flags += ["-x", opts["priv_proto"].upper(), "-X", opts["priv"]]
    return flags


VALUE_RE = re.compile(r"^(?P<oid>\.\d[\w.]*)\s*=\s*(?P<rest>.*)$", re.S)


# net-snmp prints its own presentation names; the contract asks for the
# base SMI type. Vendors disagree on the rest ("STRING" here, "DisplayString"
# in pysnmp, "OctetString" in gosnmp) and that disagreement is not a proxy
# bug, so it is normalized at the edge instead of asserted in scenarios.
TYPE_ALIASES = {
    "STRING": "OctetString",
    "INTEGER": "Integer",
    "Timeticks": "TimeTicks",
    "BITS": "OctetString",
}


def parse_value(rest):
    """Turn net-snmp's 'TYPE: value' into the contract's {type, value}."""
    if rest.startswith("No Such Object"):
        return {"type": "NoSuchObject", "value": ""}
    if rest.startswith("No Such Instance"):
        return {"type": "NoSuchInstance", "value": ""}
    if rest.startswith("End of MIB"):
        return {"type": "EndOfMibView", "value": ""}
    head, sep, tail = rest.partition(": ")
    if not sep:
        return {"type": "OctetString", "value": rest}
    kind = head.strip()
    value = tail.strip()
    if kind == "Timeticks":
        m = re.match(r"\((\d+)\)", value)
        value = m.group(1) if m else value
    if kind == "Hex-STRING":
        kind, value = "OctetString", value.replace(" ", "")
    return {"type": TYPE_ALIASES.get(kind, kind), "value": value}


NOISE = (
    "no log handling enabled",
    "failed to create the persistent directory",
    "read_config_store open failure",
    "cannot find module",
    "cannot adopt oid",
)


def useful(text):
    """Drop net-snmp's MIB/persistent-store noise, keep the real message."""
    lines = [ln for ln in text.splitlines()
             if ln.strip() and not any(n in ln.lower() for n in NOISE)]
    return "\n".join(lines).strip() or text.strip()


def classify(stderr, stdout, rc):
    text = f"{stderr}\n{stdout}".lower()
    if "timeout" in text or "no response from" in text:
        return "timeout"
    if ("unknown user name" in text or "authentication failure" in text
            or "authentication failed" in text):
        return "auth"
    if "unsupported security level" in text:
        return "security-level"
    if "decryption error" in text:
        return "decrypt"
    if "not in time window" in text:
        return "timeliness"
    if "unknown engine" in text:
        return "engine-discovery"
    if "error in packet" in text or "reason:" in text or "bad value" in text:
        return "status"
    return "error" if rc != 0 else ""


def run(argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        fail("unavailable", f"{argv[0]} not found")
    except subprocess.TimeoutExpired:
        fail("timeout", "adapter timeout")
    return proc


def main():
    opts = parse_args(sys.argv[1:])
    tool = {
        "get": "snmpget", "getnext": "snmpgetnext", "getbulk": "snmpbulkget",
        "walk": "snmpbulkwalk" if opts["version"] != "1" else "snmpwalk",
        "set": "snmpset", "trap": "snmptrap", "inform": "snmpinform",
    }[opts["verb"]]
    if shutil.which(tool) is None:
        fail("unavailable", f"{tool} not found (install net-snmp)")

    common = security_flags(opts) + [
        "-t", str(opts["timeout"]), "-r", str(opts["retries"]),
        "-On",  # numeric OIDs, keep the TYPE: value form (no -OQ: it drops the type)
    ]

    if opts["verb"] in ("trap", "inform"):
        oid = (opts["oids"] or [".1.3.6.1.6.3.1.1.5.1"])[0]
        if opts["version"] == "1":
            # SNMPv1 traps are not addressed by an OID: net-snmp wants
            # AGENT ENTERPRISE AGENT-ADDR GENERIC SPECIFIC TIMETICKS.
            enterprise = opts["enterprise"]
            specific = int(opts["specific"] or 0)
            if not enterprise:
                enterprise, _, last = oid.rpartition(".")
                enterprise = enterprise.lstrip(".")
                if not specific:
                    specific = int(last or 0)
            args = [tool] + security_flags(opts) + [
                "-t", str(opts["timeout"]), opts["target"],
                enterprise, opts["agent_addr"] or "127.0.0.1",
                str(opts["generic"] or "6"), str(specific), "",
            ]
        else:
            # net-snmp wants: snmptrap -v 2c -c comm HOST uptime trapoid [oid type value]...
            args = [tool] + security_flags(opts) + [
                "-t", str(opts["timeout"]), opts["target"], "", oid,
            ]
        for vb in opts["varbinds"]:
            vb_oid, _, rest = vb.partition("=")
            kind, _, value = rest.partition(":")
            code = SET_TYPES.get(kind.lower())
            if code is None:
                fail("usage", f"unknown varbind type {kind!r}")
            args += [vb_oid, code, value]
        proc = run(args)
        if proc.returncode != 0:
            fail(classify(proc.stderr, proc.stdout, proc.returncode) or "error",
                 useful((proc.stderr or "") + "\n" + (proc.stdout or ""))[:400])
        print(json.dumps({"ok": True, "varbinds": []}))
        return

    args = [tool] + common + [opts["target"]]
    if opts["verb"] == "set":
        if not opts["varbinds"]:
            fail("usage", "set needs --varbind oid=TYPE:value")
        for vb in opts["varbinds"]:
            oid, _, rest = vb.partition("=")
            kind, _, value = rest.partition(":")
            code = SET_TYPES.get(kind.lower())
            if code is None:
                fail("usage", f"unknown varbind type {kind!r} in {vb!r}")
            args += [oid, code, value]
    else:
        args += opts["oids"]
        if opts["verb"] == "getbulk":
            # snmpbulkget takes -Cn (non-repeaters) -Cr (max-repetitions)
            args[1:1] = ["-Cn0", "-Cr10"]

    proc = run(args)
    kind = classify(proc.stderr, proc.stdout, proc.returncode)
    detail = useful((proc.stderr or "") + "\n" + (proc.stdout or ""))
    # "No Such Object" on stdout is a status, not a failure: it is what a
    # vendor legitimately answers for a missing OID.
    varbinds = []
    for line in proc.stdout.splitlines():
        m = VALUE_RE.match(line.strip())
        if not m:
            continue
        varbinds.append({"oid": m.group("oid"), **parse_value(m.group("rest"))})

    if proc.returncode != 0 or (kind and kind != "status"):
        fail(kind or "error", detail[:400])
    print(json.dumps({"ok": True, "varbinds": varbinds}))


if __name__ == "__main__":
    main()
