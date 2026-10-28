# Testing snmp-shield

The test suite is deliberately much larger than the operational code. The
layers are ordered by independence, not by size: the higher a layer sits,
the less it can be fooled by our own encoders.

## Layers

| Layer | Where | Oracle | Cost | Runs in `make test` |
|---|---|---|---|---|
| Unit | `internal/*/..._test.go` | hand-built vectors, RFC examples | ms | yes |
| Wire e2e (Go) | `internal/usm`, `internal/tsm`, `internal/tunnel`, `internal/proxy`, `internal/access`, `internal/snmpmetrics` | gosnmp, raw datagrams, real UDP/DTLS loopback (IPv4 and `[::1]`) | seconds | yes |
| Conformance | `internal/conformance` | five independent vendor stacks driving the real binary, a vendor v3 notification **receiver** (`snmptrapd` 5.9), net-snmp 5.9 over DTLS (TSM), and two real v3 agents (host `snmpd` 5.6.2.1 + image `snmpd` 5.9.3), Docker for the container peers | ~110s | yes |
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
make conformance-required  # same matrix, but a missing toolchain FAILS (release gate)
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

## Flags-mode wiring sweep

`cmd/snmp-shield/flags_sweep_test.go` walks every role × security-mode path
(eight: manager/agent × usm-translate/passthrough, usm-gateway full and
notification-only, usm-manager-gateway, tsm-gateway) with the **full** flag
set, and asserts each config-bound flag survives assembly — twice, once with
`--read-only` and once with an explicit write policy. Two completeness
tripwires keep it from rotting: `fullOpts()` must set every `flagsOpts` field
(non-zero), and `TestOptsWiresEveryFlag` parses the real `register()` flag set
and compares the result field by field, so a flag that is registered but not
copied into `flagsOpts` fails too. Conformance finding 1 (gateway
access-policy flags dropped by an early return) is reproduced by the sweep if
the early return is reintroduced — both halves were verified by mutation.

## Conformance conventions

- **Peers are never adapted to us.** A vendor disagreement is a finding for
  `CONFORMANCE.md`, not an adapter workaround. Adapters may normalize
  presentation (e.g. net-snmp's `STRING` vs. the base type `OctetString`).
- **Assert on the contract, never on prose.** `Result.OK` and
  `Result.ErrorKind` are the assertion surface; `Result.Error` is for humans.
- **`KindUsage` means the scenario is wrong** — `mustRun` fails loudly.
  **`KindUnsupported` means the vendor cannot express the operation** —
  `skipUnsupported` skips it, so the gap stays visible without failing.
- **Missing toolchain = skip with a reason — unless the run claims to be
  complete.** `make peers` provisions the managed ones; `gosnmp` is always
  present. The TSM scenarios, the 5.9 clear-leg peer, the 5.9 v3 **agent**
  and the `snmptrapd` receiver need a Docker daemon and skip without one: the
  container carries the current net-snmp (5.9.3), while a host net-snmp may
  be Apple's 5.6.2.1 (no TLS transport, and a 2010 agent). Skips route
  through `skipOrFail`, so
  `make conformance-required` (`CONFORMANCE_REQUIRED=1`) turns every one of
  them into a failure: a release run cannot pass on a host that only ran
  gosnmp. `TestNoSkipBypassesRequiredGate` source-scans the package and fails
  when a new `t.Skip` bypasses that helper; the only sanctioned direct skip
  is `KindUnsupported` (the vendor genuinely cannot express the operation).
- **An available peer must also be runnable.** `Unavailable()` probes the
  peer's runtime through PATH as well as its data files — otherwise a peer
  whose `node` was removed still counts as present (the `node_modules`
  directory survives) and every scenario fails as an adapter error instead of
  skipping with a fixable reason. `TestMissingRuntimeSkipsInsteadOfFailing`
  pins it.
- **The notification receiver is a vendor too.** `TestUSMGatewayVendor*Receiver`
  read `snmptrapd`'s log, which it emits only after USM verification and
  decryption succeed. Nothing in that path uses our own sink: without it,
  "the manager accepted our v3 trap" was asserted by `testkit.V3Sink`, which
  is built on our own encoder (see CONFORMANCE.md, finding 6).
- **A container peer needs a routable bind.** `peerFront(t, p)` returns
  `{bind, dial}`: for a Docker peer the proxy binds `[::]` and the adapter
  rewrites the target to `host.docker.internal` (a container cannot reach
  host loopback). Native peers get one loopback address for both.
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
4. Assert with `requireOK`, `requireRefused`, `requireVarbind`; skip
   vendor gaps with `skipUnsupported`. There is deliberately no
   `requireV3Notification` helper: "the notification is really an
   authenticated v3 message" is judged by `snmptrapd` in `trapd_test.go`,
   not by a parser we wrote.
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

## What a green run does not prove

"Green" is a claim about what was actually exercised, so the gaps are listed
here rather than discovered later by someone trusting the colour. Each line
names what would close it.

- **A green `make conformance` still proves much less than a provisioned
  host.** It skips (with a reason, in `-v` output) when Docker, pysnmp or node
  are absent, and after such a run "all peers green" can mean gosnmp alone.
  `make conformance-required` now makes every such skip a failure, but nothing
  enforces running it: there is no CI by design, so the gate is only as good
  as the release checklist that calls it. Vendor limitations
  (`KindUnsupported`) still skip, correctly, even under the gate.
- **`observ` and `cmd`'s run paths are the least-covered production code**
  (measured 2026-10-28: `cmd/snmp-shield` 53.6%, `internal/observ` 0%, overall
  67.6% excluding the conformance package). Assembly coverage is now
  structural rather than incidental: the flags wiring sweep (above) exercises
  every role × mode with every flag, which closes the class conformance
  finding 1 lived in. What is still thin is process lifecycle —
  `runRole`/`Run`, signal handling, reload, logger errors — not configuration
  assembly. *Closer with:* a harness that starts the built binary per role,
  sends SIGHUP, and asserts the reload/restart-required behaviour.
- **IPv6 is covered at the socket level, not by a vendor.** One scenario per
  mode now binds `[::1]`: the USM gateway's request leg, its inform round trip
  (including the sink-discovery socket, which is separate from the request
  sockets), the manager-gateway's discovery and request sockets, the TSM
  gateway's raw DTLS front leg, and the complete two-proxy passthrough chain
  (`internal/usm/ipv6_e2e_test.go`,
  `internal/usm/gateway_inform_engine_ipv6_test.go`,
  `internal/tsm/gateway_ipv6_test.go`, `internal/proxy` IPv6 scenario). No
  peer in the matrix can be pointed at a v6 port through the peer contract —
  net-snmp wants `udp6:`/`dtls:` URLs of its own construction, and the Docker
  peers reach the host only over the IPv4 bridge name — so the family is
  judged by real sockets. Still untested: a **mixed-family** deployment (v6
  front, v4 device or the reverse), an **IPv6-only host** (where the
  `0.0.0.0`/`IPv4zero` binds rely on Go's dual-stack wildcard and would have
  to change), and scoped link-local addresses (`fe80::%en0`).
- **No soak or load run.** The rate limiter's 4096-entry cap fails closed by
  design, but nothing drives it with spoofed sources; goroutine stability is
  proven over 30 connect/close cycles, not over hours; memory is never
  measured. *Closer with:* a `make soak` (10 min, synthetic load, assert
  goroutines and RSS flat, table bounded).
- **Fuzzing is burst-mode.** Targets are run 15–30 s when a parser changes;
  the corpus runs on every `go test`, which is the important half, but long
  sessions are not continuous.
- **HA is covered as a state machine, not as an outage.** Sticky endpoint
  walk, dead-peer detection and digest-verified engine-state adoption are
  pinned; a failover while requests are in flight against two live replicas
  is not. *Closer with:* two manager-side proxies with one killed
  mid-request under continuous polling.
- **Vendor coverage means "the stacks on this host".** v1 traffic IS
  vendor-generated (`snmptrap -v 1`, `snmpget -v 1`, so v1 *translation* is
  judged by a real encoder), but no physical device is in the loop. The v3
  agent leg runs against two real agents — Apple's `snmpd` 5.6.2.1 and the
  5.9.3 in the Debian image — so a current-release divergence is visible; a
  third release (or an appliance vendor's build) is still not. TSM
  notifications have no vendor receiver at all (`CONFORMANCE.md`,
  "Deliberate limits").
- **No CI.** Regressions are caught when someone runs the suite. The
  acceptance rule in `AGENTS.md` §5 only works because it is run manually,
  every time.

## What is intentionally not here

- **No CI.** Both shield projects are run manually; the suite must be green
  on a developer machine with no network beyond loopback.
- **No cross-repo integration with modbus-shield.** That is a separate
  product.
- **No third-party TSM *receiver*.** A containerised net-snmp is a TSM
  client; `snmptrapd` cannot receive DTLS. Our notification wrapping stays
  verified by `internal/tsm`. See `CONFORMANCE.md` for the exact gap.
