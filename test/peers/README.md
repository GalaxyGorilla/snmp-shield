# External SNMP peers (interop adapters)

Third-party SNMP stacks used as conformance oracles. The proxy is tested
against them as *peers*, never adapted to them: when a vendor disagrees with
the others, that is a finding to record in `CONFORMANCE.md`, not a bug to
silence in an adapter.

| Adapter | Stack | Version here | Needs |
|---|---|---|---|
| `peer_netsnmp.py` | net-snmp CLI (`snmpget`/`snmpset`/…) | 5.6.2.1 (Apple) | `snmp` package only |
| `peer_pysnmp.py` | pysnmp (pure Python) | 7.1.30 | `test/peers/.venv` |
| `peer_node.js` | node `net-snmp` (JS) | 3.29.2 | `test/peers/node_modules` |

`scripts/peers-setup.sh` prepares the two managed toolchains (Python venv +
npm install). Both are gitignored; the Go test suite skips a peer whose
toolchain is missing and says why.

## Contract

Every adapter is an executable taking the same arguments and printing **one
JSON object** on stdout. Exit status is not the signal — the JSON is.

```
peer_<vendor> <verb> --target HOST:PORT [flags]
```

**Verbs:** `get`, `getnext`, `getbulk`, `walk`, `set`, `trap`, `inform`

**Flags**

| Flag | Meaning |
|---|---|
| `--version 1\|2c\|3` | SNMP version (default `2c`) |
| `--community C` | v1/v2c community |
| `--user U --auth A --priv P` | USM credentials |
| `--level noauthnopriv\|authnopriv\|authpriv` | explicit security level (default: derived from the credentials) |
| `--auth-proto sha\|md5\|…`, `--priv-proto aes\|des\|…` | protocols |
| `--oid OID` | repeatable; the request varbinds |
| `--varbind OID=TYPE:VALUE` | repeatable; SET values or notification varbinds |
| `--timeout SECONDS`, `--retries N` | vendor timeouts |
| `--max-repetitions N` | GETBULK |

**Result**

```json
{"ok": true,  "varbinds": [{"oid": ".1.3.6.1.2.1.1.1.0", "type": "OctetString", "value": "…"}]}
{"ok": false, "error_kind": "timeout", "error": "vendor prose, for humans only", "varbinds": []}
```

`error_kind` is the **contract**; `error` is never asserted on. Kinds:

| `error_kind` | Meaning |
|---|---|
| `timeout` | no response (the correct outcome for a silently dropped request) |
| `auth` | unknown user / wrong digest / authentication failure |
| `decrypt` | privacy failure |
| `security-level` | peer refused the requested level |
| `timeliness` | outside the RFC 3414 window (needs a re-sync) |
| `engine-discovery` | unknown engineID |
| `status` | a PDU answer with an error-status or an exception varbind |
| `indication` | vendor-side error with no better classification |
| `unavailable` | the underlying tool is not installed |
| `usage` | adapter called wrongly — a test bug, never a proxy result |

## Adding a vendor

1. Write an adapter implementing the contract above (any language).
2. Add a case to `peerKind`/`available` in `internal/conformance/peer.go`.
3. Run the matrix: `go test ./internal/conformance -v`.

Nothing else changes: scenarios are written against the contract, so a new
stack immediately runs the whole matrix — v1/v2c/v3 requests, rejections,
traps, informs, and the compatibility probes.

## Deliberate limits

- **No DTLS/TSM peers.** This host's net-snmp has no TLS support and Docker's
  daemon is not running, so no external TSM client is available. TSM is
  covered by Go-level tests only (`internal/tsm`), and the net-snmp TSM
  interop script cannot pass here. Recorded in `CONFORMANCE.md`.
- Adapters are **thin**. Anything that looks like protocol logic belongs in
  the Go suite, where the assertions are.
