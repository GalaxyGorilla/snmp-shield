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
| `netsnmp-docker/Dockerfile` | net-snmp CLI in a container (**TSM/DTLS** client) | 5.9.3 (Debian) | Docker daemon |

`scripts/peers-setup.sh` prepares the managed toolchains (Python venv + npm
install + the Docker image). The venv and `node_modules` are gitignored; the
Go test suite skips a peer whose toolchain is missing and says why.

The Docker image is not driven through the contract below: RFC 6353 needs a
`dtls:` target and a client certificate, and net-snmp refuses to check a
server certificate against an IP address at all. `internal/conformance/docker_test.go`
mounts a client identity and runs `snmpget`/`snmpwalk`/`snmpset` in it; the
scenario lives in `tsm_test.go`. It exists because a host net-snmp may be
built without TLS (Apple's 5.6.2.1 is), which would otherwise leave TSM
verified only against our own DTLS stack.

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

- **No third-party TSM *receiver*.** The Docker image is a TSM *client*:
  `snmptrapd`'s `dtls:` server mode never reads its socket (net-snmp 5.9), so
  our proxy's TSM notification wrapping is verified by `internal/tsm` and
  `scripts/tsm-sink`, not by a vendor. The request leg is verified by a
  vendor.
- **A missing Docker daemon skips the TSM scenarios**, it never fails them.
- Adapters are **thin**. Anything that looks like protocol logic belongs in
  the Go suite, where the assertions are.
