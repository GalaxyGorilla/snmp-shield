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
| Soak | `internal/access`, `internal/proxy` (`TestSoak*`) | the real binary's loops under continuous load: goroutine and live-heap graphs, a spoofed-source flood, a killed replica | 10 min | no (`make soak`, `SNMP_SHIELD_SOAK=1`) |
| Interop scripts | `scripts/interop-*.sh` | net-snmp CLI / snmpd as the peer | minutes | no (`make interop ...`) |
| Smoke | `scripts/smoke-cli.sh` | a hand-written Python v2c agent | seconds | no |
| Fuzz | `internal/{msg,access,config,cache,notifyfilter}` | the Go fuzzer | bounded | corpus only |

The Go-level wire tests use `internal/testkit` (fake device, PKI, trap sinks,
frame-sink pipe, free ports). The conformance layer uses the same scaffolding
but drives the **built CLI**, so flag parsing, defaults and validation are
covered too.

**Every privacy protocol that ships is driven by an independent stack**, not
just the one modern devices negotiate: AES-CFB (RFC 3826) throughout, and DES
(RFC 3414 §8.1.1.1) in `internal/usm/des_e2e_test.go` — a gosnmp DES client
for the request leg and a gosnmp `TrapListener` for the notification leg,
plus `internal/msg/des_test.go` for the primitive (padding, pre-IV,
malformed input). DES is the legacy protocol old devices still require, and
until that test existed **no scenario used it at all** (`EncryptDES`,
`DecryptDES` and `padBlock` measured 0%): a protocol nobody exercised against
a second implementation is a protocol that works only in theory.

## Commands

```bash
make test            # gofmt check + go test ./... -race
make vet             # go vet ./...
make conformance     # the vendor matrix only (~45s, builds the CLI once)
make conformance-required  # same matrix, but a missing toolchain FAILS (release gate)
make peers           # pysnmp venv + node net-snmp + the Docker TSM image (idempotent)
make interop         # two-proxy net-snmp interop (rc 77 without net-snmp)
make soak            # 10-minute load soak (SOAK_DURATION=90s for a quick pass)

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

## Soak tests

`make soak` runs what a functional test cannot: minutes of traffic against
the real loops, with the numbers that only a trend makes meaningful.

| Test | Asserts |
|---|---|
| `TestSoakSteadyState` (`internal/proxy`) | one two-proxy chain, a request every 20 ms: **zero** unanswered requests, worst round trip logged, goroutines at baseline ± 8, live heap (post-GC) within 24 MiB of the start |
| `TestSoakHAFailoverUnderLoad` (`internal/proxy`) | the manager polls through two replicas while the sticky one is killed at ⅓ of the budget: recovery ≤ 30 s, a green streak at the end, `snmp_shield_tunnel_reconnects_total` moved, tunnel-up gauge 1, goroutines back to baseline after teardown |
| `TestSoakRateLimiterSpoofedSources` (`internal/access`) | a flood over the whole 10/8 space: the bucket table never exceeds `limitMaxBuckets`, a never-seen source is still refused afterwards (fail-closed survives the churn), goroutines and heap flat |

They are gated behind `SNMP_SHIELD_SOAK=1` (with `SNMP_SHIELD_SOAK_DURATION`
overriding the 10-minute default), because ten minutes inside `make test`
would be ten minutes of edit loop. The gate is therefore a *release checklist
item*, not a CI one — this repository has no CI by design.

The budget is **per test**, so a full `make soak` takes about 30 minutes. A
full run on 2026-10-29:

```
steady state   10m0s, 27386 requests, worst round trip 39ms,
               goroutines 26 (baseline 26, peak 26), live heap 0.9MiB -> 1.1MiB
HA failover    10m0s, failover after 8.092s (4 failures), 17177 answers after
               the kill, final streak 17177, teardown back to baseline
rate limiter   10m0s, 1036288 admitted / 4238498006 refused, table 4096/4096,
               goroutines 2, heap flat
```

That is the shape the numbers should have: flat goroutines, a heap that does
not track the request count, an outage measured in seconds, and a rate-limiter
table that stops at its cap instead of following the flood.

**They earn their keep.** The first runs found three real defects that every
functional test had answered requests straight through:

1. `passthrough.Agent.bgctx()` built a context **and a watcher goroutine per
   send**, discarding the cancel: one goroutine leaked per request (and per
   notification) until shutdown. 50 req/s is 4.3M goroutines a day.
2. `passthrough.Agent.awaitAgentResp`/`awaitInformResp` waited out the full
   15 s timeout even after the answer arrived, holding a goroutine and a
   pending entry each — a steady state of rate × 15 s goroutines.
3. `tunnel.Session` never closed its subscriber channels, so an accepted
   session's `for f := range ch` loops (`reqLoop`, `notifRespLoop`,
   `respLoop`, `sinkLoop`) parked forever: one goroutine set leaked **per
   reconnect**, which a flaky WAN would turn into thousands over days.
4. `tunnel.Session.readLoop` fired `Done()` only on the exits that dropped
   the connection themselves. A server answering a PING whose PONG write
   fails drops the conn *inside* the loop (`dropConn`, TunnelDown fires),
   then finds no connection and returned **silently** — `Done()` never
   fired, so the per-session translator was never cancelled and the
   goroutine kept its `max_sessions` slot and the active-session gauge
   forever. That is the failure mode the session cap exists to prevent: a
   handful of clients that vanish mid-exchange would deny the service.
   Fixed with a `defer s.closeDone()` in the loop (the loop is the only
   reader and is started once, so its exit *means* the session is over);
   the now-redundant per-exit calls were removed so the invariant has one
   home. Pinned deterministically by
   `TestReadLoopExitFiresDoneAfterFailedPong` (`internal/tunnel`), which
   feeds a PING over a fake conn whose writes fail. Found by running the
   panic test under `-coverpkg=./...`: the instrumentation slowed the loop
   enough to reach the PING branch, which the normal suite never did.

The fast regression net is `TestNoPerRequestGoroutines` (`internal/proxy`,
not soak-gated): 200 requests must not add 10 goroutines, and teardown must
return to baseline. Reverting the two passthrough fixes reproduces it as
`goroutines 36 at steady state, 436 during 200 requests`. Finding 4 is the
complement: a goroutine count cannot see a session that *never ended*, so
the session's own exit invariant is pinned directly rather than by counting.

Scope limit: the goroutine net drives requests, and the soak's steady-state
traffic is GETs — the **inform** pending maps (passthrough and the USM manager,
both fixed here) are pinned functionally by their round-trip tests, not by a
goroutine count. An inform leak would therefore still need a soak run with
inform traffic to surface.

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
- **The process lifecycle lives here too** (`lifecycle_test.go`), even though
  it involves no vendor. It is the only place a real signal can be delivered
  without firing into the test binary's own process, and `systemctl reload` /
  `systemctl restart` are the operator's actual interface. These tests never
  skip — no peer, no Docker — so a bare host's green run still says something
  about shutdown and reload.

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
  The port can be taken between the probe and the bind — seen once under full
  suite load (plus a second suite running on the same host, which is why you
  should run one at a time) as a product-looking
  `bind: address already in use` on a gateway trap listener. Readiness now
  goes through `(*proxyProc).waitFront`, which stops the moment the process
  exits and prints its log, so that failure says "exited before binding …
  address already in use" instead of a 10 s timeout. `awaitFront` is the
  testable half and is pinned by `TestAwaitFrontFailsFastWhenTheProcessExited`
  — a hand-built dead `proxyProc`, because a UDP dial to a non-local address
  reports "bound" (UDP has no connect handshake to fail).
- **A readiness budget must exceed the production startup budget.** The
  manager eagerly dials the tunnel with a 10 s timeout *before* it starts the
  translator that binds the clear leg (`runManager`: a failed connect is only
  a warning, the translator starts anyway). A fixture that waits 10 s for that
  leg therefore collides exactly with the design: under full-suite load one
  DTLS handshake took the whole budget and the failure read "manager never
  bound …", which looks like a bind bug. `frontReadyTimeout` is 30 s for that
  reason. Whenever a role gains a startup timeout, check the fixtures that
  wait on it.
- **Wait for a real answer, not for a bound socket.** A bound UDP port does
  not prove the tunnel behind it works: `waitV2cReady` polls an end-to-end
  GET.
- **macOS UNIX socket paths are limited to 104 bytes** (`sun_path`). Bind
  test sockets in a short `os.MkdirTemp` path, not `t.TempDir()` (which
  embeds the test name).
- **Close client connections before stopping a server**; a raw DTLS read
  blocks until the peer closes.
- **Never assert on a clean close over UDP — assert the design's bound.** A
  DTLS `close_notify` is a single datagram with no retransmission, so a test
  that closes a client and waits for the server to notice is racing packet
  loss: it passes a thousand times and then fails under load for no product
  reason. The cap tests therefore shorten the fallback they actually rely on
  (`frontIdleTimeout` via `SetFrontIdleTimeoutForTest`, `keepalive_secs: 1`
  for the tunnel's 9×keepalive dead-peer window) and, in the TSM case, leave
  the last client conn **open** so the idle bound is what must return the
  slot. Without that, `TestTSMGatewaySessionCap` and
  `TestRunAgentSessionCap` both failed in a full run while passing in
  isolation.
- **Test proxies log to a buffer** that is printed only when the test fails.
  Rerun a failing scenario with `-v` and add `--log-level debug` to the
  fixture when diagnosing a wire problem.
- **A cold chain may drop the first request — wait for a real answer.** The
  tunnel is a live stream, not a replay queue: a frame that reaches the
  agent-side proxy before its per-session translator has subscribed is
  discarded. For `usm-translate` that first request also *triggers* engine
  discovery, so the loss costs a full discovery timeout (5 s) and the
  manager's read loop is blocked while it waits. A real SNMP manager retries,
  so the product is fine; a test that measures "the first request works"
  measures startup timing instead. `waitChainReady` (in
  `internal/proxy/goroutines_test.go`) polls until an answer arrives before
  any measurement — under `-race` the window is wide enough that the
  non-retrying version failed every run.

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
- **The signal edge is covered on a real process, but only for the shapes
  listed** (`internal/conformance/lifecycle_test.go`, measured 2026-10-30:
  `cmd/snmp-shield` 86.0%, `internal/observ` 100%, overall 67.5% excluding the
  conformance package). Assembly coverage is structural rather than
  incidental: the flags wiring sweep (above) exercises every role × mode with
  every flag, which closes the class conformance finding 1 lived in. The
  `selftest` probes are driven against real wire peers (`selftest_test.go`)
  and the reload path runs from a YAML file to the wire twice — in-process
  (`internal/proxy/reload_e2e_test.go`, which can call `reloadConfig`
  directly) and on the **built binary** (`TestProcessSIGHUPReloadsAccessPolicy`:
  real SIGHUP, read-only takes effect on the next SET with no restart,
  SIGTERM exits 0; `TestProcessSIGHUPIsNotShutdown`: SIGHUP in flags mode is a
  logged no-op and the process keeps serving). Both are mutation-verified —
  adding SIGHUP to the shutdown context fails the second, dropping `h.Store`
  fails the first. `TestProcessBindFailureIsLoud` pins the other half of the
  startup contract: a front leg that cannot bind exits non-zero with the
  cause logged (a unit that looks healthy while serving nothing is worse than
  a failed start). It binds TEST-NET-1 rather than an in-use port, because
  UDP `SO_REUSEADDR` lets a second bind through on macOS — the same test
  would pass for the wrong reason on one platform and fail on the other.
  A request in flight when the signal lands is covered too
  (`TestProcessShutdownUnderLoad`: a device that holds the request for 400 ms,
  SIGTERM mid-flight, exit 0 well inside the 15 s pending-request timer, no
  panic in the log, and the client's call returns rather than hanging) — that
  is the shape a join-instead-of-cancel shutdown would fail. What remains
  uncovered: *draining* (a request accepted before the signal is deliberately
  dropped, so nothing asserts it is answered), a peer that keeps sending
  while the process stops, the systemd watchdog's STOPPING notification (no
  systemd in a test), and `manager`/`agent` role signals — only `gateway` is
  driven here, though the wiring is shared, so that is one code path, not
  three. *Closer with:* a `systemctl stop` contract that drains in-flight
  work, if that is ever wanted.
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
- **The soak is opt-in, so `make test` still proves nothing about hours.**
  `make soak` (10 min, `SNMP_SHIELD_SOAK=1`) now drives the two-proxy chain
  under continuous polling, floods the rate limiter with spoofed sources and
  kills a replica mid-poll; the first runs found three real defects (a
  goroutine leak per send, a 15s goroutine per answered request, and
  subscriber goroutines that outlived their session — see the findings below).
  What it still does not show: days of uptime, a real WAN (loss/reorder/jumbo
  MTU), RSS as opposed to live heap, and concurrent client fan-in rather than
  one sequential poller.
- **Fuzzing is burst-mode.** Targets are run 15–30 s when a parser changes;
  the corpus runs on every `go test`, which is the important half, but long
  sessions are not continuous.
- **HA is now pinned as an outage, but only one shape of it.**
  `TestSoakHAFailoverUnderLoad` (soak-gated) polls continuously through a
  manager with two agent-side replicas and kills the sticky one mid-run:
  recovery must land within 30s (3 idle misses × 3×keepalive plus a redial),
  the run must end in a green streak, and teardown must not strand
  goroutines. Not covered: a replica dying during a *write* (a half-applied
  SET), both replicas flapping, and a failover while informs are in flight.
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
