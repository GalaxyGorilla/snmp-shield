# Testing snmp-shield

The test suite is deliberately much larger than the operational code. The
layers are ordered by independence, not by size: the higher a layer sits,
the less it can be fooled by our own encoders.

## Layers

| Layer | Where | Oracle | Cost | Runs in `make test` |
|---|---|---|---|---|
| Unit | `internal/*/..._test.go` | hand-built vectors, RFC examples | ms | yes |
| Wire e2e (Go) | `internal/usm`, `internal/tsm`, `internal/tunnel`, `internal/proxy`, `internal/access`, `internal/snmpmetrics` | gosnmp, raw datagrams, real UDP/DTLS loopback | seconds | yes |
| Conformance | `internal/conformance` | four independent vendor stacks driving the real binary, plus net-snmp 5.9 over DTLS (TSM) in Docker | ~45s | yes |
| Interop scripts | `scripts/interop-*.sh` | net-snmp CLI / snmpd as the peer | minutes | no (`make interop ...`) |
| Smoke | `scripts/smoke-cli.sh` | a hand-written Python v2c agent | seconds | no |
| Fuzz | `internal/{msg,access,config,cache,notifyfilter}` | the Go fuzzer | bounded | corpus only |

The Go-level wire tests use `internal/testkit` (fake device, PKI, trap sinks,
frame-sink pipe, free ports). The conformance layer uses the same scaffolding
but drives the **built CLI**, so flag parsing, defaults and validation are
covered too.

## Commands

```bash
make test            # gofmt check + go test ./... -race
make vet             # go vet ./...
make conformance     # the vendor matrix only (~45s, builds the CLI once)
make peers           # pysnmp venv + node net-snmp + the Docker TSM image (idempotent)
make interop         # two-proxy net-snmp interop (rc 77 without net-snmp)

go test ./internal/conformance -v -count=1          # see which peers ran/skipped
go test ./internal/conformance -run TestUSMGatewayRequests -v
```

Static analysis and supply chain (run after dependency or parser changes):

```bash
staticcheck ./...
govulncheck ./...
make vulnscan        # SBOM + grype, fails on HIGH+
```

## Conformance conventions

- **Peers are never adapted to us.** A vendor disagreement is a finding for
  `CONFORMANCE.md`, not an adapter workaround. Adapters may normalize
  presentation (e.g. net-snmp's `STRING` vs. the base type `OctetString`).
- **Assert on the contract, never on prose.** `Result.OK` and
  `Result.ErrorKind` are the assertion surface; `Result.Error` is for humans.
- **`KindUsage` means the scenario is wrong** — `mustRun` fails loudly.
  **`KindUnsupported` means the vendor cannot express the operation** —
  `skipUnsupported` skips it, so the gap stays visible without failing.
- **Missing toolchain = skip with a reason.** `make peers` provisions the
  managed ones; `gosnmp` is always present. The two TSM scenarios need a
  Docker daemon and skip without one: their peer is net-snmp 5.9 in a
  container, because a host net-snmp may have no TLS transport at all.
- **A vendor cannot be pointed at an IP in TSM.** net-snmp compares the
  server certificate against the *name* dialed, so the container dials
  `dtls:host.docker.internal:port`, the proxy listens on `[::]` (a container
  cannot reach host loopback), and the test PKI issues the server certificate
  with that SAN (`testkit.NewPKIWithNames`).
- Every scenario starts its own proxy process on ephemeral ports and its own
  fake device; nothing is shared between subtests.

## Adding a scenario

1. Put it in `internal/conformance/<session>_test.go`.
2. Use `eachPeer(t, func(t *testing.T, p Peer) { ... })` so it runs against
   every stack automatically.
3. Build the fixture with `startProxy` (real binary) and
   `testkit.NewAgent`/`NewV3Sink`/`NewTrapSink`, or one of the existing
   `start*` helpers in the package.
4. Assert with `requireOK`, `requireRefused`, `requireVarbind`,
   `requireV3Notification`; skip vendor gaps with `skipUnsupported`.
5. Prefer OIDs unique to the scenario: `WaitForTrapOID` searches everything
   the sink has seen.

## Adding a peer

1. Write an adapter implementing `test/peers/README.md` (any language).
2. Add it to `AllPeers()` in `internal/conformance/peer.go`.
3. Run `go test ./internal/conformance -v`.

Nothing else changes: scenarios are written against the contract, so a new
stack immediately runs the whole matrix.

## Test isolation rules (learned the hard way)

- **Ephemeral ports only.** Bind `127.0.0.1:0` and read `LocalAddr()`; fixed
  loopback ports flake under `-race` because packages run in parallel.
- **`FreeUDPPort` is a probe, not a reservation.** Use it only where a config
  must name an address before anything binds; retry through a real request.
- **Wait for a real answer, not for a bound socket.** A bound UDP port does
  not prove the tunnel behind it works: `waitV2cReady` polls an end-to-end
  GET.
- **macOS UNIX socket paths are limited to 104 bytes** (`sun_path`). Bind
  test sockets in a short `os.MkdirTemp` path, not `t.TempDir()` (which
  embeds the test name).
- **Close client connections before stopping a server**; a raw DTLS read
  blocks until the peer closes.
- **Test proxies log to a buffer** that is printed only when the test fails.
  Rerun a failing scenario with `-v` and add `--log-level debug` to the
  fixture when diagnosing a wire problem.

## Fuzzing

Go-native targets, one per wire-facing decoder. Run longer locally with:

```bash
go test ./internal/msg        -run '^$' -fuzz 'Fuzz' -fuzztime 30s
go test ./internal/access     -run '^$' -fuzz FuzzAllowed -fuzztime 30s
go test ./internal/config     -run '^$' -fuzz FuzzLoad -fuzztime 30s
go test ./internal/cache      -run '^$' -fuzz FuzzLoadEngine -fuzztime 30s
go test ./internal/notifyfilter -run '^$' -fuzz 'Fuzz' -fuzztime 30s
```

| Target | Invariant |
|---|---|
| `msg`: Peek, SplitV1V2c, ParsePDU, SplitV1Trap, ParseV3, UnwrapScopedPDU, TrapOID, DecodeOID | error, never panic; TLVs stay inside the datagram |
| `msg: FuzzParseVarbinds` | parse/re-encode round-trips; malformed lists are errors |
| `access: FuzzAllowed` | fail closed: unreadable/empty SET is denied, even by an allow-all policy; non-SET PDUs pass |
| `config: FuzzLoad` | a config that loads is fully compilable; otherwise a clean error |
| `cache: FuzzLoadEngine` | a corrupt engine store is a hard error and is never rewritten; boots never regress |
| `notifyfilter: FuzzAllowed/FuzzNew` | total classification; allow/deny are complementary; prefix matching is monotone |

Crashers and failing inputs land in `testdata/fuzz/` and run as normal test
cases afterwards.

## What is intentionally not here

- **No CI.** Both shield projects are run manually; the suite must be green
  on a developer machine with no network beyond loopback.
- **No cross-repo integration with modbus-shield.** That is a separate
  product.
- **No third-party TSM *receiver*.** A containerised net-snmp is a TSM
  client; `snmptrapd` cannot receive DTLS. Our notification wrapping stays
  verified by `internal/tsm`. See `CONFORMANCE.md` for the exact gap.
