# AGENTS.md — snmp-shield

> **Read this file first. Update it at the end of every task** — behavior,
> layout, commands, decisions. Treat it as documentation-as-code.

## 1. Mission

This project is a **SNMP securing proxy**. From the original author:

> "This is a fresh project. I want you to work on a SNMP proxy that is capable
> of securing an existing SNMP line. The idea here is that this proxy is thrown
> in between a SNMP client and server, one proxy in front of each entity,
> securing the line via USM or TSM. The whole thing needs to work as good as
> possible with v2 and v3."

Deployment model:

```
[manager] --UDP (clear)--> [manager-side proxy]
       === secured segment ===
       [agent-side proxy] --UDP (clear)--> [real SNMP agent]
```

Two instances of one binary; each secures its local clear leg and encrypts the
long-haul segment between them.

## 2. Decisions (do not re-litigate without strong reason)

| Topic | Decision |
|---|---|
| Language | **Go** |
| Tunnel transport | **DTLS over UDP** (primary) + **TLS over TCP** (alternative) |
| First capability | **Passthrough tunnel**, then USM/TSM message security |
| SNMP versions | v2c and v3 are priority; v1 tolerated on clear leg |
| Config | YAML file per instance, role via subcommand |
| HA | Manager dials a list (`tunnel.dial_addrs`, sticky last-known-good); dead peers detected via keepalive (3 misses × 3×keepalive) and per-session work is cancelled through `Session.Done()`; replicas sharing one engineID converge on the highest seen engine state: digest-verified higher boots adopted as logical reboot, manager adopts Reports from ANY engineID and follows the wire for same-engine boots/time changes |

## 3. Status / Roadmap

**Current state: all five security modes complete — passthrough,
usm-translate (two-proxy tunnel), tsm (two-proxy tunnel), usm-gateway
(single box, standard v3 in / clear v2c out; notification-only and
both-leg deployment shapes; the former usm-manager mode is merged in as
the notification-only shape), and tsm-gateway (single box,
SNMP-over-DTLS RFC 6353 in / clear v2c out); informs confirmed in ALL
gateway modes (usm + tsm round-trip e2e-pinned); no-YAML CLI mode
implemented and smoke-tested end-to-end; cache package unit-tested;
net-snmp CLI interop-tested end-to-end for the two-proxy chain (incl.
trap direction), the USM gateway (incl. trap direction and rejection of
clear/wrong-user traffic), and the TSM gateway (snmpget/getnext/
bulkwalk/set, untrusted-client rejection, trap direction).**

| Milestone | Status |
|---|---|
| Scaffold: dirs, go.mod, .gitignore, AGENTS.md | done |
| Config package (YAML + flags, both roles, security.mode) | done (tested) |
| Logging/metrics baseline (zap + Prometheus) | done |
| Tunnel: DTLS/UDP + TLS/TCP dialer/listener | done (tested) |
| Passthrough forwarding v1/v2c/v3 (GET/GETNEXT/GETBULK/SET, traps/informs) | done (tested) |
| E2E harness (Go/gosnmp client + fake Go agent on loopback) | done |
| USM translate mode (v1/v2c <-> v3 authPriv, engineID discovery, boots/time cache) | done (tested, interop vs gosnmp) |
| TSM mode (cert-based security model on tunnel leg) | done (tested) |
| Cache package unit tests (store persistence, engine clocks, replay) | done (tested) |
| Net-snmp interop tests (snmpget/getnext/bulkwalk/set/trap; needs `apt-get install snmp`) | done (tested, `scripts/interop-snmp.sh`) |
| USM gateway mode (standard v3 manager → single proxy → legacy agent) | done (tested, gosnmp + net-snmp `scripts/interop-gateway.sh`, incl. trap direction) |
| TSM gateway mode (RFC 6353 SNMP-over-DTLS front leg) | done (tested, Go harness + net-snmp `scripts/interop-gateway-tsm.sh`, incl. trap direction) |
| PSK ciphersuite variety (`tunnel.psk_ciphersuites`: aes128-ccm-8 default, aes256-ccm-8, aes128-ccm, aes128-gcm, aes128-cbc; YAML + `--psk-ciphersuites` flag) | done (tested, unit + per-suite loopback handshakes + mismatch rejection) |
| Notification filtering (`notifications.filter`: allow/deny OID prefixes; YAML + `--filter-oid`/`--filter-action` flags) | done (tested, unit + e2e: passthrough relay, USM gateway w/ gosnmp TrapListener; config validation) |
| HA (manager tunnel failover `tunnel.dial_addrs` sticky walk; keepalive dead-peer detection 3 misses × 3×keepalive; session Done()/per-session cancel; USM cross-engine Report adoption; live `keepalive_secs`/`max_reconnect_backoff_secs` + Reconnects/TunnelUp metrics) | done (tested, failover e2e + dead-peer net.Pipe + config/flags tests; smoke + all 3 interop suites re-run green) |
| USM two-proxy chain in-Go e2e tests (`internal/usm/translate_manager_e2e_test.go`: full manager+agent translator chain over a pipe shim, fake v2c agent; discovery/GET, trap relay+filter, agent-notif→sink, inform round trip) + **inform relay bug fix** (manager-side informs were never answered) | done (tested, -race -count 2) |
| msg fuzz tests (`internal/msg/fuzz_test.go`: 8 Go-native fuzz targets — Peek/SplitV1V2c/ParsePDU/SplitV1Trap/ParseV3/UnwrapScopedPDU/TrapOID/DecodeOID; regression corpus in `testdata/fuzz/`) + **2 parser panic fixes** (berOctetStringLike empty-buffer, ParseV3 declared-length overflow) | done (tested, all targets fuzzed 30s green; corpus runs in every `go test`) |
| TSM inform relay fix + e2e tests (`tsm_e2e_test.go`: inform round trip device→sink→device, agent-originated inform answered; pipe pending-queue fix for the startup race) — same dead-end as USM (FlagInform RESP frames never matched against the inform pending map, `ip.addr` never set) | done (tested, -race -count 2) |
| internal/proxy wiring e2e tests (`internal/proxy/proxy_test.go`: white-box runAgent/runManager/runGateway over real PSK-DTLS loopback; passthrough + usm-translate two-proxy chains, USM + TSM gateways driven by gosnmp/DTLS clients, parseEngineID) + **2 prod fixes pinned**: TSM gateway accept loop returned "listener closed" error on clean shutdown (pion returns its own sentinel, not net.ErrClosed) and passthrough Manager `m.conn` read races its deferred nil-write (serveClearRequests/awaitResponse now read under socksMu) | done (tested, -race -count 2; proxy 0% → ~72% coverage) |
| crypto primitive unit tests (`internal/usm/crypto_test.go`: protocol parsers, key lengths, RFC 3414 A.3 password-to-key vectors, Blumenthal/Reeder priv-key extensions, digest/sign/verify round trips + aliasing, DES salt counter) + cmd flags/os.Args coverage (`main_test.go`: gateway branches, psk-ciphersuites + filter flags, parsePskCiphersuites, run() version/help/genpsk/unknown) | done (tested, -race -count 2; crypto.go ~100%, cmd 24% → 57%) |
| Manager-securing single proxy: **usm-manager mode** (now MERGED into usm-gateway as its notification-only deployment shape: `security.mode: usm-gateway` with `gateway.trap_listen_addr` + `gateway.trap_sink_addr` instead of `listen_addr`/`agent_addr`; clear v1/v2c traps/informs at `trap_listen_addr` → v3 USM authPriv notifications toward `trap_sink_addr`, own authoritative engine + first user; inform responses relayed back to the device; usm-manager mode name hard-removed — no alias) | done (tested, gosnmp TrapListener sink incl. auto-inform-response oracle, trap/inform/v1/filter tests ported into `internal/usm/gateway_test.go` (`TestGatewayTrapRelay`, `TestGatewayInformRoundTrip`, `TestGatewayV1TrapNotif`, `TestGatewayNotifFilter`), -race -count 1; validation requires one leg pair or both) |
| Meaningful challenge tests (adversarial/edge-case tests beyond happy paths, added where they find real issues) + pragmatic polish | done (tested, `internal/usm/gateway_challenge_test.go` + `internal/tunnel/challenge_test.go`: stale engineTime rejected w/ usmStatsNotInTimeWindows report, tampered digest rejected w/ usmStatsWrongDigests, non-reportable silent drop, GetBulk relay, garbage-datagram robustness, wrong-PSK handshake rejection; polish: removed unreachable GetBulk-on-v1 downgrade in gateway.go — `downstreamFor` always returns v2c) |
| HA pair state sync (failover replicas sharing one engineID converge: digest-verified higher-boots claims adopted as logical reboot via `cache.EngineClock.AdoptInbound`; manager discovery cache follows the wire for same-engine Report regressions) | done (tested, `internal/usm/ha_sync_test.go` wire tests + cache unit test; smoke + all 3 interop suites re-run green) |
| Notify filtering for the usm-manager manager-side notification path | done (already implemented at birth: `GatewayTranslator.handleClearTrap` filters clear notifications before the v3 wrap toward `trap_sink_addr`, `TestGatewayNotifFilter` covers it; the v3 notification is generated from that ingress so the hook covers the whole path) |
| Gateway inform consistency (all gateway modes confirm informs): **usm-gateway inform fix** (port of the usm-manager machinery: `readTraps` single-reader v3-vs-clear `msg.Peek` dispatch, `gwInformPend` keyed on the v3 msgID sent to the sink, fresh req-id inform rebuild, `handleSinkResponse` verify/decrypt with keys localized to the SINK's engineID from the wire, clear GetResponse rebuilt with the device's req-id/community, send FROM trapConn not sendUDP, wait goroutine so the read loop never blocks, 15s timeout with pointer-identity delete) + **tsm-gateway inform fix** (same dead-end — `sinkConn` was write-only, `g.inform` never consulted: `serveSinkConn` read loop on the reusable sink DTLS session, `gwInformPending` gains `outReqID`/`ver`/`community`/`ready`, inform keyed on the OUTGOING gateway req-id (`wrapTSM` req-id echo rule), clear GetResponse rebuilt with the device's `info.RequestID`, timeout fail-safe `reqTimeout` 15s) | done (tested, `TestGatewayInformRoundTrip` (gosnmp TrapListener auto-inform-response oracle) + `TestTSMGatewayInformRoundTrip` (in-test raw-DTLS TSM sink that reads and replies), -race -count 1; `TestTSMGatewayTrapDirection` still green) |
| Static analysis (staticcheck + govulncheck toolset, pragmatic: fix only meaningful findings) | done (tested, staticcheck zero findings — dead code removed, pion/dtls v3.1.4 upgrade for GO-2026-6165, options-API migration; govulncheck clean) |
| `validate` subcommand (`--role` + same flags/`--config`; `--json` for tooling; pre-flights cert keypairs, CA files, engine-store writability) + `selftest` subcommand (validate + probes: tunnel handshake per endpoint (manager), SNMP GET sysDescr.0 to the real agent (agent/gateway), front-cert expiry (tsm-gateway); `--probe=false`) | done (tested, unit tests + manual live-agent/tunnel/dead-addr verification) |
| `validate --json` exit-code fix (rc mirrors `ok` in both output modes; previously `validate --json` returned 0 on invalid configs while `selftest --json` always honored rc 1 — README/AGENTS "Exit 0/1" only held for text mode) | done (tested, unit + live rc verification; full race suite re-run green) |
| Makefile (`make build/test/vet/release`), systemd units (`deploy/*.service`: hardening, CAP_NET_BIND_SERVICE, StateDirectory), examples directory (6 copy-paste walkthroughs), README rewrite | done |
| README decision guidance (native SNMPv3, WireGuard/IPsec, and `snmpfwd` alternatives; snmp-shield's DTLS/TSM and appliance-operations fit) | done |
| Goroutine-leak regression test (`internal/tunnel/leak_test.go`: 30 connect/exchange/close cycles over real PSK-DTLS loopback, goroutine count must return to baseline; server side keyed on `Session.Done()` + production `SetTuning` so there is no test-end accounting noise) | done (tested, -race -count 8 stable: before=after=5) |
| SBOM + automated vuln-DB comparison (`make sbom` → syft SPDX+CycloneDX into `dist/`; `make vulnscan` → `grype db update` + `grype --fail-on high` vs NVD/GHSA/OSV; `scripts/sbom.sh --sbom-only`) + x/crypto v0.48.0 → v0.58.0 upgrade clearing all Critical/High advisories (go directive 1.24 → 1.26, mandatory for x/crypto ≥ 0.56) | done (tested, `make vulnscan` rc=0 — only residual GO-2026-5932 is Unknown severity/unfixed deprecated-openpgp advisory, below the gate; direct symbol-precise binary scan: 0 findings) |
| SNMP metrics interface (`internal/snmpmetrics`: read-only SNMPv2c health MIB GET/GETNEXT on `metrics.listen_addr` + v2c tunnel-lifecycle traps to `metrics.trap_sink_addr`; `Session.SetEventFunc` events, all roles; Prometheus stays alongside) | done (tested, unit tests + e2e: two-proxy chain polling + tunnel-down trap pinned) |

### Gateway modes (single proxy, no second proxy required)

Motivation: today USM/TSM security only exists **between our own two
proxies** (the tunnel leg). A normal industry-standard manager cannot
authenticate to a single proxy, because the only USM-termination path
sits behind the private tunnel envelope (PSK-DTLS + our frame protocol),
and the manager-facing clear leg only parses v1/v2c. Gateway modes open
the front door to third-party clients, making the deployment 100%
standard SNMP on every wire — important for firewalls/ALGs/DPI and
auditors. The proxy protecting the (v2c-only) agent **is the asset's
security gate**: unauthenticated traffic never reaches the legacy
device.

**1. USM gateway (`usm-gateway`)** — the valuable one — **IMPLEMENTED
(see below)**:

```
[any standard manager] --SNMPv3 USM authPriv (RFC 3414)--> [proxy] --clear v2c--> [legacy agent]
```

- Front leg terminates USM directly from any normal manager
  (net-snmp, Zabbix, PRTG...): proxy is the authoritative engine toward
  the manager — RFC 3414 discovery Reports, engineBoots/engineTime
  (persisted, anti-rollback), user database = `security.users`
  (auth verify + priv decrypt), timeliness/replay window.
- Clear v1/v2c arriving on the front leg is **rejected** — that
  rejection is the protection.
- Back leg relays the authenticated request as clear v1/v2c to the old
  agent (existing translation path).
- Traps/informs reverse: old agent fires clear traps at the proxy →
  proxy wraps them into authenticated v3 USM notifications toward the
  manager (trap-wrapping code exists, repointed at the manager).
- Mostly wiring: the engine (`cache.EngineClock`, discovery,
  verify/decrypt) already exists on the agent-side tunnel leg.

### USM gateway design (as implemented)

- New role `gateway` + `security.mode: usm-gateway` (no tunnel). Config:
  `gateway.listen_addr` (front leg, plain UDP), `gateway.agent_addr`
  (legacy agent), `gateway.agent_community` (v2c community toward the
  agent), optional `gateway.trap_listen_addr` (clear traps from the
  legacy network) and `gateway.trap_sink_addr` (manager's v3 USM trap
  receiver). Users come from `security.users` (auth verify + priv
  decrypt); `security.engine_store` persists the authoritative engine
  boots (REQUIRED, anti-rollback); optional fixed `security.engine_id`.
- `internal/usm/gateway.go` — `GatewayTranslator` mirrors the
  agent-side termination path (translate_agent.go handleTunnelRequest):
  ParseV3 → engine-ID check (discovery answered by `dropOrReport`
  Reports) → timeliness (`cache.EngineClock.AcceptInbound`) →
  `Profiles.Lookup` → sec-level enforcement → auth verify → priv
  decrypt → forward as v1/v2c (GetBulk→GetNext downgrade on v1);
  responses correlated by a map keyed on the downstream request-id;
  clear v1/v2c on the front leg is rejected (`rejectClear`).
- Trap direction: clear v1/v2c traps at `trap_listen_addr` are wrapped
  into v3 authPriv notifications (first configured user, own engine
  state) and sent to `trap_sink_addr`.
- No-YAML CLI mode: `snmp-shield gateway --listen :161 --agent
  127.0.0.1:161 --community public --auth-pass <auth> --priv-pass
  <priv> [--trap-listen :162 --trap-sink <mgr>:162]`.
- Tests: `internal/usm/gateway_test.go` (gosnmp v3 authPriv client as
  independent oracle: discovery+GET, wrong-user rejection, clear-v2c
  rejection, trap direction validated by a gosnmp TrapListener);
  `scripts/interop-gateway.sh` drives the gateway with real net-snmp
  v3 clients (snmpget/getnext/bulkwalk/set, wrong-user + clear-v2c
  rejection, snmptrap direction; skips rc 77 without net-snmp).

**2. TSM gateway (`tsm-gateway`)** — RFC 6353 front leg — **IMPLEMENTED
(see below)**:

```
[standard TSM client] --SNMP-over-DTLS (RFC 6353)--> [proxy] --clear v2c--> [legacy agent]
```

- Front leg is a (D)TLS listener in a new **raw mode**: one SNMP
  datagram = one (D)TLS record, **no frame layer** (DTLS preserves
  record boundaries per Read — `internal/tunnel/stream.go` already
  relies on this, so raw mode needs zero framing logic).
- Reuse `internal/tsm/tsm_agent.go` logic unchanged: peer cert →
  securityName, `tsm_identities` allow-list, unwrap scopedPDU, forward
  clear v2c; responses/traps mirrored.
- Caveat: almost no industry-standard manager speaks TSM (net-snmp
  does, Zabbix/PRTG don't) — implemented as bonus after USM gateway.

### TSM gateway design (as implemented)

- Same `gateway` role as the USM gateway, `security.mode: tsm-gateway`
  (no tunnel, no engine clock). Config: `gateway.listen_addr` (raw
  DTLS front leg), `gateway.agent_addr`, `gateway.agent_community`,
  optional `gateway.trap_listen_addr` / `gateway.trap_sink_addr`
  (manager's TSM trap receiver). Cert material on the **tunnel**
  config keys (`tunnel.ca_file`/`cert_file`/`key_file`): the raw
  front listener needs a server cert; `security.tsm_identities`
  allow-lists client certificate identities (empty = accept any valid
  cert).
- `internal/tunnel/listener.go` gained `ListenRaw` (raw mode, DTLS
  only — TLS/TCP is a byte stream with no record boundaries): Accept
  hands out the `*dtls.Conn` as-is (no `streamConn` buffering), each
  Read = one SNMP datagram.
- `internal/tsm/tsm_gateway.go` — `TSMGateway`: front DTLS sessions
  (one per manager), handshake = authentication (peer cert CN →
  `tsm_identities`), unwrap TSM v3 (plaintext scopedPDU, secModel 4),
  forward as clear v2c to the legacy agent; responses correlated by a
  map keyed on the downstream request-id. Clear v1/v2c traps at
  `trap_listen_addr` are wrapped into TSM v3 notifications (reusable
  DTLS session toward `trap_sink_addr`).
- **TSM response echo rule** (learned from net-snmp
  `snmpv3_verify_msg`, which validates every field): responses echo
  the request's msgID, request-id, contextEngineID, securityName and
  security-level flags (auth/priv bits), even though TSM secParams
  stay empty.
- No-YAML CLI: `snmp-shield gateway --security tsm-gateway --listen
  :10161 --agent 127.0.0.1:161 --ca-file certs/ca.crt --cert-file
  certs/server.crt --key-file certs/server.key [--trap-listen :10162
  --trap-sink <mgr>:10162]`.
- Tests: `internal/tsm/gateway_test.go` (DTLS client with cert →
  gateway → fake v2c agent: GET, wrong-identity silence, trap
  direction); `scripts/interop-gateway-tsm.sh` drives the gateway
  with real net-snmp TSM clients over `dtls:` (snmpget/getnext/
  bulkwalk/set, untrusted-client rejection, trap direction via
  `scripts/tsm-sink` raw-DTLS receiver; skips rc 77 without
  snmpget/openssl).

### TSM design (RFC 5591, as implemented)

- `security.mode: tsm`: the tunnel (D)TLS handshake **is** the SNMP
  authentication. Messages carry `secModel=4` with an **empty**
  securityParameters OCTET STRING; the clear PDU rides in the scopedPDU.
- securityName = peer certificate leaf CN (falls back to first DNS SAN,
  then email). The agent side allow-lists identities
  (`security.tsm_identities`, empty = accept any valid cert) via
  `Session.PeerCerts()` (`tunnel.PeerCertConn`); pion/dtls exposes DER
  chains decoded through `x509.ParseCertificate`.
- Manager side wraps v1/v2c PDUs in TSM v3 messages; agent side unwraps,
  checks the peer, forwards as v2c (`agent.agent_community`); responses,
  traps and informs mirror the flow. No USM crypto, no engine discovery.

## 4. Repository Layout

```
cmd/snmp-shield/           main package; role via subcommand (manager|agent|gateway) + validate/selftest/genpsk
internal/config/          YAML config + flag overrides
internal/proxy/           shared proxy wiring
internal/passthrough/     opaque forwarding of clear SNMP
internal/notifyfilter/    notification allow/deny OID filtering
internal/usm/             USM translate + gateway modes (incl. notification-only) + profiles
internal/tsm/             TSM mode + TSM gateway mode
internal/tunnel/          DTLS/TLS tunnel dialer/listener (+ PSK ciphersuite mapping)
internal/msg/             SNMP message build/parse helpers
internal/cache/           engine boots/time cache (anti-rollback, persistence)
internal/discovery/       engineID discovery per RFC 3414
internal/securitylevel/   securityLevel constants/validation
internal/observ/          zap logging + Prometheus metrics
internal/snmpmetrics/     SNMP health MIB agent + tunnel event traps
```

(Directories with code: config, observ, tunnel, msg, passthrough, proxy,
usm, tsm, cache, notifyfilter, snmpmetrics, cmd/snmp-shield. Still empty, reserved:
discovery (discovery logic lives in internal/usm translate_manager.go),
securitylevel. Also: configs/ example YAML (manager/agent × psk/usm/tsm +
gateway-usm + gateway-tsm + gateway-usm-manager [usm-gateway
notification-only]), scripts/gen-certs.sh
throwaway test PKI into gitignored certs/, scripts/tsm-sink raw-DTLS
test receiver for interop, scripts/sbom.sh SBOM+vulnscan entry point,
deploy/ systemd unit files, examples/
deployment walkthroughs, Makefile (build/test/vet/release/sbom/vulnscan).)

## 5. Build / Test

Go 1.27.2 at `/usr/local/go/bin/go` (on PATH via `/etc/profile.d/go.sh`);
go.mod declares minimum **1.24.0** (CI-free project — tests run manually).

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

`make build` / `make test` / `make vet` / `make release` wrap the same
commands (`release` = stripped static binary, `CGO_ENABLED=0
-trimpath -ldflags "-s -w"`, for appliance deployment).

**Static analysis** (installed in `~/go/bin`, run after every dependency
change or parser edit — pragmatic: fix only meaningful findings):

```bash
~/go/bin/staticcheck ./...
~/go/bin/govulncheck ./...
```

**SBOM + vulnerability scan** (installed in `~/go/bin`, run after every
dependency change or before a release):

```bash
make sbom       # release binary -> syft -> dist/snmp-shield.{spdx,cdx}.json
make vulnscan   # grype db update + grype --fail-on high vs NVD/GHSA/OSV
```

`vulnscan` depends on `sbom` (which builds `release` first). Tools:
syft + grype (Anchore; `GOBIN=$HOME/go/bin go install
github.com/anchore/{syft/cmd/syft,grype/cmd/grype}@latest`). Missing
tools → exit 77 (skip), like the interop scripts. `scripts/sbom.sh`
runs the same flow standalone (`--sbom-only` skips the scan).

**Acceptance for every commit**: build + vet + `go test -race ./...` clean.
Note: non-login shells may not have `go` on PATH — use `/usr/local/go/bin/go`
or set `-timeout` on `go test` (DTLS tests would hang without one).

### No-YAML CLI mode (plug-and-play deployment)

Without `--config`, the subcommands build a validated Config from direct
flags. Two-proxy deployment is two commands plus a generated key:

```bash
KEY=$(snmp-shield genpsk)   # random 32-byte hex key
snmp-shield agent   --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass <auth> --priv-pass <priv> --agent 127.0.0.1:161 --community public
snmp-shield manager --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass <auth> --priv-pass <priv> --listen :161 --community public
```

Flags: `--tunnel-mode` (dtls|tls), `--tunnel-addr` (manager role:
comma-separated endpoint list ip:port,ip:port — HA failover, most
preferred first; agent role: single listen address), `--psk-identity`,
`--psk-ciphersuites`
(comma-separated DTLS PSK suites, most preferred first: aes128-ccm-8 |
aes256-ccm-8 | aes128-ccm | aes128-gcm | aes128-cbc; default
aes128-ccm-8), `--insecure`, `--security` (usm-translate|passthrough),
`--trap-listen`, `--trap-sink`, `--filter-oid` (repeatable OID prefix) +
`--filter-action` (allow|deny; notification filtering, see §7),
`--metrics-snmp-listen` / `--metrics-snmp-trap-sink` /
`--metrics-snmp-community` / `--metrics-snmp-base-oid` (SNMP metrics
interface, see §7).
Both sides must share `--psk`/`--auth-pass`/`--priv-pass` and at least
one `--psk-ciphersuites` entry. Default security
in flags mode is usm-translate (user 'proxy', SHA, AES).

Gateway (single box, no tunnel/PSK):

```bash
snmp-shield gateway --listen :161 --agent 127.0.0.1:161 \
  --community public --auth-pass <auth> --priv-pass <priv> \
  [--trap-listen :162 --trap-sink <manager>:162]
```

TSM gateway (single box, RFC 6353 DTLS front leg — cert-based):

```bash
snmp-shield gateway --security tsm-gateway --listen :10161 \
  --agent 127.0.0.1:161 \
  --ca-file certs/ca.crt --cert-file certs/server.crt \
  --key-file certs/server.key \
  [--trap-listen :10162 --trap-sink <manager>:10162]
```

USM gateway notification-only (single box, protects the manager leg:
clear devices in, authenticated v3 out toward the manager's trap
receiver — usm-gateway with only the trap legs):

```bash
snmp-shield gateway --security usm-gateway \
  --trap-listen :162 --trap-sink <manager>:162 \
  --auth-pass <auth> --priv-pass <priv>
```

### validate / selftest subcommands

Appliance/tooling helpers (web-UI pre-apply + "test connection"):

```bash
snmp-shield validate --role <manager|agent|gateway> \
  [--config <file> | same flags as the role] [--json]
snmp-shield selftest --role <manager|agent|gateway> \
  [--config <file> | same flags as the role] [--json] [--probe=false]
```

- `validate` loads + validates the config and pre-flights local
  resources (cert keypair loads, CA parses, engine-store writable).
  Exit 0/1. `--json` prints the report document for tooling.
- `selftest` = validate + probes: config, local files, tunnel
  (D)TLS handshake per configured endpoint (manager role), one SNMPv2c
  GET sysDescr.0 to the real agent with 2 attempts (agent role +
  gateway modes), front-cert expiry warning at 30 days (tsm-gateway).
  `--probe=false` for no-network checks. Exit 0 = all checks passed.
- Both share the full flag set with the role subcommands via one
  `register()` function (`cmd/snmp-shield/diagnostics.go`); unknown
  flags for a given subcommand are simply unused. The selftest probes
  work while the service is running (no listener binding needed — the
  tunnel probe is a client dial, the agent probe is a one-shot GET).

### Smoke test

`scripts/smoke-cli.sh` — plug-and-play end-to-end: builds the binary, starts
agent+manager via flags plus a fake Python v2c agent (hand-built BER),
polls with `go run ./scripts/smoke-client <port>`. Exit 0 = green.

### net-snmp interop test

`scripts/interop-snmp.sh` — drives the two-proxy chain (PSK-DTLS,
usm-translate) with real net-snmp CLI clients: snmpget, snmpgetnext,
snmpbulkwalk, snmpset, and snmptrap (full trap direction) against a fake
Python v2c agent on a tiny 2-OID MIB (sysDescr.0, sysObjectID.0; increasing
GETNEXT/GETBULK walk, endOfMibView/noSuchInstance exceptions). Requires
`apt-get install snmp`; exits 77 (skip) when tools are missing. Exit 0 =
green.

**Trap direction (usm-translate mode, verified by this script):** devices
fire at the **manager-side** proxy's `--trap-listen`; the manager-side
translator wraps the v1/v2c trap into a v3 NOTIF frame across the tunnel;
the **agent-side** proxy unwraps, verifies, and delivers the plain v2c
notification (community = `security.trap_sink_community`, fallback
`public`) to its `--trap-sink`. The agent-side translator has **no** clear
trap listener in usm-translate mode.

### net-snmp gateway interop test

`scripts/interop-gateway.sh` — drives the single-box gateway with real
net-snmp v3 USM authPriv clients: snmpget, snmpgetnext, snmpbulkwalk,
snmpset (relayed as clear v2c to the fake agent), wrong-user rejection,
clear-v2c rejection on the front leg (the protection), and snmptrap
direction (clear v2c trap at the gateway's `--trap-listen` → v3 USM
notification at the sink). Same fake-agent MIB and skip behavior as
`interop-snmp.sh`. Exit 0 = green.

### net-snmp TSM gateway interop test

`scripts/interop-gateway-tsm.sh` — drives the single-box TSM gateway
with real net-snmp TSM clients over `dtls:` (RFC 6353): snmpget,
snmpgetnext, snmpbulkwalk, snmpset (relayed as clear v2c), untrusted-
client rejection (client cert from an unknown CA), and trap direction
(clear v2c trap at `--trap-listen` → TSM v3 notification captured by
`scripts/tsm-sink`, a raw-DTLS receiver). Self-contained: generates a
throwaway PKI and a temp net-snmp HOME (`tls/ca-certs` + `tls/certs` +
snmp.conf with `clientCert`/`trustCert` sha256 fingerprints). Needs
`snmpget` + `openssl`; exits 77 (skip) when missing. Exit 0 = green.

## 6. Key Dependencies (go.mod)

- `github.com/gosnmp/gosnmp` — SNMP v1/v2c/v3 (USM) marshalling, requests
- `github.com/pion/dtls/v3` — DTLS tunnel
- `github.com/prometheus/client_golang` — metrics
- `github.com/spf13/pflag` — CLI flags
- `go.uber.org/zap` — structured logging
- `gopkg.in/yaml.v3` — config parsing
- `golang.org/x/crypto`, `golang.org/x/sys` — indirect (pion); keep current —
  `make vulnscan` gates releases on their advisories

## 7. Design Notes

- Passthrough mode must forward v3 messages **with USM parameters byte-exact**
  so end-to-end engineID/boot/time verification between manager and agent
  still works; the proxy never needs to decrypt in this mode.
- USM translate mode is the harder path: proxy owns engineID discovery
  (RFC 3414 §3.2 discovery + ping/pong), tracks engineBoots/engineTime per
  engine with anti-rollback (never accept decreasing boots/time; persist to
  disk), and converts v1/v2c <-> v3 authPriv messages in both directions.
- TSM (RFC 5591) maps the tunnel's (D)TLS peer certificate to a securityName;
  the tunnel handshake then *is* the SNMP authentication.
- Traps/informs flow both directions: devices -> manager-side proxy -> tunnel
  -> agent-side proxy -> real manager.
- **Manager-side tunnel wiring must call `sess.Connect(ctx)` eagerly** before
  starting a translator: the first Send on a lazy session races the DTLS
  handshake and the first app record can be silently lost (pion's server-side
  handshake only starts once the client writes).
- USM translate architecture: the agent-side proxy owns the authoritative
  engine (requests + its own trap engine); the manager-side proxy owns its
  own engine for traps it originates. Translation is PDU splicing (v1/v2c
  community wrapper <-> v3 header+USM+scopedPDU), req-id preserved from the
  client PDU end-to-end. All PDU field access goes through `msg.ParsePDU`
  (single parser; the old ad-hoc BER walkers were removed after subtle
  tag/length-position bugs).
- Engine state: `cache.EngineClock` generates or adopts an engineID,
  increments boots per start (persisted JSON in `security.engine_store` —
  REQUIRED, boots must never decrease), engineTime = seconds since start.
  Inbound timeliness per RFC 3414 §3.2 (±150 s window, anti-rollback);
  a digest-verified HIGHER boots claim is adopted as a logical reboot
  (HA pair state sync, see below).
- **HA (tunnel failover + dead-peer detection)**:
  - Manager dials a list: `tunnel.dial_addrs` (YAML, most preferred
    first; supersedes `tunnel.dial_addr`, which still works as the
    single-entry form). The Dialer walks endpoints starting at the
    sticky last-known-good index; each endpoint gets the full dial
    timeout; the first success pins the index. `--tunnel-addr` accepts a
    comma-separated list in flags mode.
  - **pion `dtls.Dial` does NOT handshake** — it returns instantly and
    the handshake completes lazily on first Read/Write, so a dead
    endpoint "dials" successfully. `Dialer.Dial` now runs
    `HandshakeContext` eagerly inside the dial goroutine (bounded by the
    dial timeout) so per-endpoint failures surface to the failover walk.
  - Dead-peer detection: `Session.SetTuning(keepalive, maxBackoff)`
    sets the read deadline to 3×keepalive; after 3 consecutive idle
    timeouts the connection is dropped (client probes with PING first;
    server just drops and its readLoop returns, firing `Session.Done()`).
    0 values = legacy behavior (90s deadline, never declare dead, 5s
    backoff cap). `keepalive_secs`/`max_reconnect_backoff_secs` are now
    live config (were dead code before). `Session.Close()` fires Done.
  - Agent-side proxy cancels per-session translators via
    `Session.Done()` → per-session context (previously the translator
    leaked per reconnect until process exit).
  - USM manager adopts a Report from ANY engineID (`handleReport`
    cross-engine rule): after failover, requests to the stale engineID
    are answered by the new replica's unknownEngineID Report and
    discovery switches automatically. A same-engine Report also follows
    the wire even when boots/time regress (the failed-over replica's
    announcement); real anti-rollback lives engine-side — the
    authoritative engine rejects stale requests with a notInTime Report
    carrying its CURRENT state, which re-syncs this cache.
  - **HA pair state sync** (`cache.EngineClock.AdoptInbound`): replicas
    sharing `security.engine_id` but keeping separate engine stores have
    different boots; the failover replica's LOWER persisted boots would
    otherwise be stuck rejecting the old higher claims forever. Fix: in
    `translate_agent.go handleTunnelRequest` + `gateway.go
    handleFrontRequest`, the timeliness check is deferred until AFTER
    digest verification, and a verified HIGHER boots claim is adopted as
    a logical reboot (RFC 3414), re-anchoring engineTime to the claimed
    timeline and persisting the merged state. Unverified claims
    (NoAuthNoPriv or any failed digest — `verified` is only set after an
    actual `Verify`) never adopt: pre-auth rejection and same-boots
    replay protection unchanged. Tests: `internal/usm/ha_sync_test.go`
    (failover serves, unverified rejected w/ usmStatsNotInTimeWindows,
    manager Report follow-the-wire) + cache unit test.
  - Metrics now wired: `Reconnects` counter + `TunnelUp` gauge set by
    the session on reconnect/drop.
- **USM inform relay (bug fix, pinned by e2e)**: in usm-translate mode,
  device-facing informs (PDUInformRequest arriving on the manager's clear
  trap listener) are tracked in `ManagerTranslator.informPend` keyed by a
  fresh tunnel corrID (the device's req-id is remembered), sent as NOTIF
  frames with `tunnel.FlagInform`; the agent side answers via
  `sendInformResponse` (RESP frame, FlagInform, corrID preserved); the
  manager's `handleTunnelInformResp` matches the corrID, unwraps with
  per-engine keys and rebuilds the clear v2c GetResponse for the device
  (req-id echoed from the response, falling back to the remembered
  client req-id). Before the fix the inform response was dropped by
  `handleTunnelResponse` ("no pending request") and informs timed out
  RFC-3411-style. The sender address is tracked best-effort
  (`lastInform`, stashed by `readTraps` on inform detection) since UDP
  gives no per-message reply address on the response path. The manager's
  inbound notif path (`handleTunnelNotif`) additionally answers
  agent-originated informs with a RESP FlagInform frame echoing the
  inform's USM params (engine/boots/time/user) and req-id.
- **TSM inform relay (bug fix, pinned by e2e)**: identical dead-end to the
  USM one — `ManagerTranslator.handleClearTrap` tracked informs in
  `m.inform` but the Run loop's RESP dispatch never consulted that map
  (responses were dropped by `handleTunnelResponse`, "no pending request")
  and the sender address was discarded by `readTraps`. Fixed symmetric to
  USM: `readTraps` stashes `lastInform`, the informPending carries
  ver/community/addr, the device's req-id is preserved end-to-end
  (`handleClearTrap` wraps informs with `info.RequestID`, not the
  manager's counter), Run's RESP dispatch routes FlagInform frames to
  `handleTunnelInformResp` (rebuilds the clear GetResponse at the sender),
  and `handleTunnelNotif` answers agent-originated informs (sink now
  optional on that path). Agent-side answers now echo the inform's
  msgFlags (TSM response echo rule). **RFC 5591 nuance learned**: TSM
  secParams are EMPTY on the wire (`BuildV3` drops USMParams for
  secModel=4) — the securityName/flags echo rule applies only to what
  actually rides the wire (msgID, req-id, contextEngineID, auth/priv
  bits); there is no securityName to echo inside TSM secParams, so
  asserting a non-empty `m2.USM.UserName` on a TSM message is always
  wrong. Also fixed the TSM e2e pipe shim's startup race (frames sent
  before the peer subscribed are now queued per frame-type and delivered
  on Subscribe — mirrors real tunnel buffering; non-blocking/dropping
  sends made the trap path flake ~20% of runs).
- **TSM gateway inform fix (bug fix, pinned by e2e)**: the tsm-gateway
  had the same dead-end as the pre-fix usm-gateway — bookkeeping theater:
  `handleClearTrap` registered `gwInformPending{addr, deviceID}` in
  `g.inform` keyed on the DEVICE's req-id, but the sink conn was
  write-only (no Read anywhere), `g.inform` was never consulted, and the
  entry was just deleted after the 15s timeout — the manager's TSM
  GetResponse was dropped, the device retransmitted and timed out. Fixed:
  `gwInformPending` gained `outReqID/ver/community/resp/ready`; informs
  are keyed on the **gateway's OUTGOING req-id** (mint once before
  `wrapTSM` — per the TSM response echo rule the manager echoes that
  req-id in its GetResponse); each NEW reusable sink DTLS session gets a
  `serveSinkConn` read loop (one Read = one datagram, DTLS preserves
  record boundaries) that parses the TSM v3 response, matches
  `g.inform[fields.ReqID]`, rebuilds the clear v2c GetResponse with the
  DEVICE's `info.RequestID` + original community and relays it to the
  device address; the 15s `reqTimeout` is the fail-safe cleanup
  (pointer-identity delete). On read error the session is dropped so the
  next notification redials. Pinned by `TestTSMGatewayInformRoundTrip`
  (in-test raw-DTLS TSM sink that reads and replies — the sink side of
  the round trip is hand-built with exported msg primitives since
  `wrapTSM` is unexported).
- **Pipe-shim test lesson** (`translate_manager_e2e_test.go`): an
  in-memory FrameSink shim must deliver frames via **blocking** channel
  sends — non-blocking sends silently drop frames that arrive before the
  peer's Run loop has subscribed (discovery then times out); the real
  tunnel blocks, so the shim must too. Also: `ManagerTranslator.Run`
  binds its own socket on `cfg.ListenAddr` — a test harness must pass
  the wanted port in the config and use a separate `DialUDP` sender
  socket (reading `mgr.conn` from the test goroutine races Run).
  And: `msg.ParseV3`'s `m.PDU` is the ciphertext TLV (tag 0x04) for
  priv-flagged messages until `unwrapV3` decrypts in place — check the
  inner PDU type on the unwrapped `plain` TLV, not `m2.PDU[0]`.
- **proxy e2e test gotchas** (`internal/proxy/proxy_test.go`): run the
  unexported `runAgent`/`runManager`/`runGateway` directly with a
  cancelable ctx (`Run` installs a signal.NotifyContext, untestable);
  `config.Defaults()` is a METHOD — call it explicitly, runX does not;
  `security.engine_store` must be a FILE path (`t.TempDir()` bare is a
  directory and cache.Open fails with "is a directory"); the manager
  clear leg speaks v1/v2c in usm-translate mode (drive it with a v2c
  client — the v3 leg is the tunnel); `stopRun` consumes the single
  buffered errCh value, so deferred cleanup must cancel only (never
  `<-errCh` twice). DTLS clients dial with `tunnel.Dialer` (eager
  handshake), never `tls.DialWithDialer("udp", ...)` — TLS-over-UDP is
  not DTLS. `serveFront`-style raw sessions block on Read until the
  client closes: close client conns BEFORE cancelling the gateway.
- **pion/dtls accept-error sentinel**: pion's UDP listener returns its
  own `ErrClosedListener = errors.New("udp: listener closed")` on Accept
  after Close — NOT `net.ErrClosed`. Any accept loop that must return
  nil on clean shutdown has to match both (tsm_gateway does a
  strings.Contains fallback).
- **msg fuzzing** (`internal/msg/fuzz_test.go`): 8 Go-native fuzz
  targets cover every parser entry point (Peek, SplitV1V2c, ParsePDU,
  SplitV1Trap, ParseV3, UnwrapScopedPDU, TrapOID, DecodeOID) with
  invariants (version ∈ {0,1}, TLVs inside datagram, TSM ⇒ empty
  secParams, DecodeOID round-trip vs a canonicalOID reference).
  Run longer locally: `go test ./internal/msg -run '^$' -fuzz 'Fuzz'
  -fuzztime 30s`. Crashers land in `internal/msg/testdata/fuzz/` and
  run as normal test cases in every `go test`. Fuzzing found two
  wire-reachable panic classes (both fixed, pinned by corpus):
  (a) **empty-buffer tag read in the error-formatting path** —
  `berOctetStringLike` formatted `buf[0]` into the error message when
  the buffer was empty (v1 trap PDU with empty content); panics kill
  the trap-listener goroutine. (b) **declared-length overflow past the
  outer buffer in TLV-advance arithmetic** — `berContent` only checks
  its own input, so callers computing `tag+lenOctets+content` offsets
  (ParseV3 header advance) must re-check against the OUTER buffer.
  General rule: any slice arithmetic combining a parsed length with
  parsed content needs a bounds check against the original datagram.
- **USM gateway notification-only shape (former usm-manager mode,
  MERGED into usm-gateway)** (`internal/usm/gateway.go`,
  `security.mode: usm-gateway` with `gateway.trap_listen_addr` +
  `gateway.trap_sink_addr` instead of `listen_addr`/`agent_addr`): the
  proxy protects the **manager** leg. Clear v1/v2c traps/informs arrive
  at `gateway.trap_listen_addr`; the proxy wraps each into a v3 USM authPriv
  notification (own authoritative engine state from `cache.EngineClock` +
  first configured user; PDUInformRequest for informs, PDUSNMPv2Trap for
  traps; v1 traps translated via V1TrapToV2 first) and sends it to
  `gateway.trap_sink_addr` (the manager's trap receiver). Validation
  requires (ListenAddr AND AgentAddr) OR (TrapListenAddr AND TrapSinkAddr)
  — one leg pair or both (gateway branch). `GatewayTranslator.Run` binds
  front/agent only when ListenAddr != "" (notification-only supported).
  **Inform round trip** (shared by full and notification-only shapes):
  informs are confirmed — the proxy tracks a
  `gwInformPend{addr, community, ver, clientReqID, resp, ready}` keyed on
  the v3 msgID it sent, waits up to 15s (in a goroutine — the wait must
  NOT block the trap read loop); the single `readTraps` loop (same socket,
  dispatches v3 vs clear by Peek) parses the manager's
  v3 GetResponse, verifies/decrypts it with keys localized for the
  **sink's engineID from the response wire** (`profilesFor(m.USM.EngineID)`
  — the response is signed/encrypted by the sink's own engine, same pattern
  as inbound notifications), matches the pending inform, rebuilds the
  clear v2c GetResponse (device req-id echoed, original community) and
  relays it back to the device address **directly from
  handleSinkResponse with the pend pointer** — the pend is deleted from
  the map before the wait goroutine wakes, so a msgID-based re-lookup
  there would dead-end and the device would never see its response.
  Traps are fire-and-forget. Notification filtering applies at the clear
  ingress. The inform is sent FROM the trap listener socket (WriteTo),
  not sendUDP — the manager's response arrives at the packet's source
  address, which must be the trap listener (one reader dispatches both
  directions; competing ReadFrom loops would steal each other's
  datagrams). The old `internal/usm/manager_gateway.go` is DELETED (its
  4 tests ported into `gateway_test.go`); the mode name is hard-removed
  (no alias) — `usm-manager` now fails config validation.
- **Challenge-test semantics** (`internal/usm/gateway_challenge_test.go`,
  `internal/tunnel/challenge_test.go`): the security gate is pinned
  adversarially on the wire — same-boots out-of-window engineTime claims
  are rejected with a
  Report whose varbind carries usmStatsNotInTimeWindows (counter suffix
  2), tampered PDUs (one flipped byte) with usmStatsWrongDigests (suffix
  5); WITHOUT the Reportable flag the same attacks are dropped in
  complete silence (RFC 3414 §4). (A stale-boots attack is pointless
  since the HA state-sync rule: a verified HIGHER boots claim is a
  legitimate logical reboot and is adopted — stale-time on the same
  boots is the reproducible rejection.) Hostile datagrams (empty,
  truncated
  headers, huge declared lengths, non-BER noise) never kill the front
  listener. Wrong-PSK DTLS clients fail the handshake (Connect error).
  Gotchas for similar tests: `msg.Peek` returns PDUType 0 for v3
  datagrams (the scopedPDU is opaque) — assert the Report's PDU type via
  `msg.ParseV3(dg).PDU[0]`; a fake agent that only answers GET (0xA0)
  makes GetBulk tests time out — echo GET/GETNEXT/GETBULK; gosnmp
  derives the auth/priv MsgFlags from the SecurityParameters' protocols
  (SHA/AES set the bits even when you pass NoAuthNoPriv — a genuine
  NoAuthNoPriv wire message needs empty protocols).
- **validate/selftest design** (`cmd/snmp-shield/diagnostics.go`): the
  probes are deliberately non-binding — the tunnel probe is a plain
  client dial (works while the service holds the tunnel), the agent
  probe is a one-shot SNMPv2c GET sysDescr.0 built with `msg.BuildPDU`
  (raw varbind-list content: a varbind TLV wrapped in the 0x30
  varbind-list SEQUENCE) so no gosnmp dependency is needed in cmd, and
  the cert-expiry probe only WARNS at 30 days (ok=true) — expired is a
  failure. `checkEngineStore` mirrors `cache.Open` semantics
  (O_RDWR|O_CREATE on the file path; a directory in place fails; parent
  dirs are NOT created). `--json` reports go to stdout (tooling reads
  them), human errors go to stderr with exit 1. **Exit-code contract
  (fixed)**: rc mirrors `ok` in BOTH output modes — `validate --json`
  previously returned 0 on invalid configs (its JSON branch
  short-circuited) while `selftest --json` always honored rc 1 via the
  shared tail check; tooling can now trust `validate … --json || abort`
  and still parses the `ok` field for details. JSON mode prints only
  the JSON document (no trailing human summary).
- **Goroutine-leak testing** (`internal/tunnel/leak_test.go`,
  `TestSessionGoroutineLeak`): the session layer is pinned against
  goroutine leaks with 30 connect/exchange/close cycles over a real
  PSK-DTLS loopback pair — `runtime.NumGoroutine()` must return to
  baseline. Two harness gotchas learned while building it:
  (a) the server side MUST key its goroutines on `Session.Done()` and
  mirror production tuning (`SetTuning(keepalive, 0)`) — a harness
  parked on a test-end `<-cancel` channel leaks one goroutine set per
  cycle and flags false positives (63 "leaked" goroutines that were
  just harness accounting); (b) without `SetTuning`, the server's
  legacy 90s read deadline outlives the 3s leak-check window, so the
  pion handshake goroutine + read loop are still parked at measurement
  time — flaky across runs. With both fixes the count is exactly
  stable (before=after=5 over 30 cycles, -count 8 green).
  **macOS flake (fixed with a watchdog)**: even with both fixes, on
  macOS pion's server-side Read can park past the app-level read
  deadline while the handshake FSM is not fully settled — the server's
  `readLoop` sits in `readFull` for minutes, `Done()` never fires, and
  a bare `<-sess.Done()` wedges the whole suite (timeout at the suite
  level, test passes in isolation). Fix: the server-side wait is
  bounded by a 2s watchdog that force-`Close`s the session — Close
  fires Done through the SAME exit path, so a genuinely leaked session
  still fails the goroutine-count check (the watchdog only neutralizes
  the harness-level wedge). -count 4 green on Linux, -count 4 + -count 3
  ×2 + full suite green on macOS/arm64 (homebrew Go).
- **SBOM + vuln scan** (`make sbom` / `make vulnscan`, syft + grype):
  syft catalogs the stripped release ELF — Go buildinfo survives
  `-s -w` (the binary pseudo-version is crafted from build settings),
  so the SBOM carries every go.mod module with its exact version
  (21 packages incl. stdlib). **grype DB freshness matters**: a fresh
  grype install ships a weeks-old DB and refuses to scan (max age 5
  days) — automation MUST run `grype db update` first. Gate is
  `grype <sbom> --fail-on high`. **Symbol vs module granularity**:
  scanning the SBOM matches at module granularity (conservative, may
  report false positives); scanning the binary directly
  (`grype bin/snmp-shield`) matches symbols precisely — e.g. after the
  x/crypto v0.58.0 upgrade the SBOM still reports GO-2026-5932
  (module-level "x/crypto/openpgp is unsafe by design", Unknown
  severity, no fix exists — the package is deprecated, not patched)
  while the direct binary scan finds 0: openpgp is not linked in (we
  only pull cryptobyte/chacha20/poly1305 via pion). Both are correct;
  the SBOM gate at `--fail-on high` passes. Syft's
  `SYFT_GOLANG_CAPTURE_SYMBOLS=all` did NOT add symbol data to the
  SBOM in this build (SPDX/CycloneDX identical for stripped and
  unstripped binaries) — don't fight it; module-granularity SBOM
  matching + direct-binary spot checks is the pragmatic combination.
  x/crypto v0.48.0 → v0.58.0 cleared all Critical/High advisories;
  x/crypto ≥ 0.56 requires `go 1.26.0`, so the module go directive
  moved 1.24.0 → 1.26.0 (mandatory, not cosmetic).
- **Notification filtering** (`internal/notifyfilter`, `notifications.filter`):
  one filter (action allow|deny + dotted OID prefixes) applies at the
  **clear-notification ingress points only** (the 6 `handleClearTrap`/
  `serveClearTraps` sites: passthrough agent+manager, usm
  translate_manager+gateway, tsm manager+gateway); tunnel NOTIF→sink
  delivery paths are NOT re-filtered (already filtered at the far-side
  ingress; agent-side usm/tsm translators have no clear trap listeners).
  Matching is prefix-based on arc boundaries ("1.3.6.1.4.1.99" does NOT
  match "1.3.6.1.4.1.9999"); the trap OID comes from `msg.TrapOID`:
  v2c reads the snmpTrapOID.0 varbind, v1 traps derive the RFC 2576
  translated form (enterprise.0.specific for generic 6, else
  snmpTraps.(generic+1)) — the same OID shape the relay itself produces,
  so filters written for v3 traps also match v1 traps after translation.
  Extraction failure (no snmpTrapOID.0, malformed) matches nothing:
  allow→drop, deny→forward. Non-notification datagrams on trap ports
  pass unchanged. Constructors take a variadic filter (`From(filt...)`),
  keeping existing call sites compiling. Dropped notifications increment
  `snmp_shield_notifications_filtered_total`. Validation runs in
  `Config.Validate` before the gateway branch (which returns early).
- **SNMP metrics interface** (`internal/snmpmetrics`, `metrics.` config
  section): every role can serve a small read-only SNMPv2c health agent
  (`metrics.listen_addr`, GET/GETNEXT only, community-gated; wrong
  community and malformed datagrams are silently dropped) and emit v2c
  event traps (`metrics.trap_sink_addr`). MIB layout (default base
  `.1.3.6.1.4.1.58427.1`, configurable `metrics.base_oid`): .1 product,
  .2 version, .3 role, .4 securityMode, .5 tunnelMode, .6 tunnelEndpoints,
  .7 uptimeSecs, .10 tunnelUp, .11 tunnelEndpoint, .20.<n> counters
  (1-based rows in `Metrics.CounterList()` order — a compatibility
  contract, never reorder), .30 latencyCount, .31 latencySum. Events
  subtree (traps): .2.1 tunnel up (varbind-less distinction: .2.3 is sent
  instead when the event is an HA failover), .2.2 tunnel down.
  Wiring: `tunnel.Session.SetEventFunc` (tunnel-up/down/failover events,
  emitted from reconnect/dropConn; failover = sticky dialer index changed)
  → `installTunnelEvents` (proxy.go) updates the scalars and sends the
  trap; agent role hooks every accepted server session. Traps are
  fire-and-forget v2c (sysUpTime.0 + snmpTrapOID.0), sent from the MIB
  listener socket when it is bound, else from a dedicated ephemeral
  socket (trap-only configuration). Prometheus (--metrics-addr) stays
  available alongside. Gotchas learned building it:
  (a) **lexicographic OID comparison is wrong for GETNEXT** — dotted
  strings sort ".10" before ".7"; the walk must compare arc-by-arc
  numerically (`parseArcs`/`arcsAfter`).
  (b) **a nil *net.UDPConn inside a net.PacketConn interface is
  non-nil** — the trap sender's `currentConn()` must nil-check the
  typed pointer, not the interface, or WriteTo panics on a nil receiver.
  (c) dotted OID strings carry a leading dot in accessor form but
  `msg.EncodeOID` rejects it — normalize (TrimPrefix) before encoding;
  the config default base OID is dotted-with-leading-dot while raw flag
  values may lack it, so both trap-OID joining and the MIB agent
  normalize defensively.
  (d) prometheus instruments expose values via `Write(*dto.Metric)`
  (Collect takes a channel — wrong API).
- gosnmp quirks (interop oracle; learned the hard way):
  - gosnmp encrypts the **full scopedPDU TLV** (outer SEQUENCE header
    included) and expects the same from us — `msg.BuildV3` mirrors this.
  - Response decrypt uses the client's **cached** engine boots/time (the
    values from our previously announced message), not the incoming
    response's USM fields — agent-side responses always encrypt with the
    engine state the peer last saw.
  - Discovery = Reportable|NoAuthNoPriv empty GET; ANY response's USM
    params update its engine state, then it retransmits with authPriv.
    Our `dropOrReport` Report (reqID = triggering msgID, usmStats OID
    varbind) is exactly what it needs; reports to authed users are signed
    with that user, discovery reports stay NoAuthNoPriv.
  - `UsmSecurityParameters` must be `InitSecurityKeys()` + `InitPacket()`
    before `MarshalMsg()` in tests.
  - Response PDU request-id must match the request's req-id (or 0); the
    v3 header msgID is not validated.
  - Responses need ≥1 varbind unless errStatus is set.
  - gosnmp's TrapListener **can** validate our authPriv v3 notifications:
    it re-derives keys from the wire engineID (so our own engine state
    works as authoritative engine), verifies the digest per the message's
    MsgFlags, and decrypts with wire boots/time/salt. Attach
    `Params.Logger = gosnmp.NewLogger(...)` when debugging — silent
    rejects otherwise.
  - In `TrapListener.OnNewTrap` callbacks, OID varbinds decode
    `v.Value` as a **dotted string with a leading dot** (".1.3.6.1..."),
    NOT `[]string` — type-asserting `[]string` panics the callback.
- net-snmp quirks (stricter than gosnmp; learned via
  `scripts/interop-gateway.sh`):
  - **INTEGER encoding must be minimal two's-complement**: a positive
    value whose top content byte has the high bit set needs a leading
    `0x00` octet. `AppendInteger`/`AppendUint32` (internal/msg/ber.go)
    encode this; msgMaxSize=65535 previously encoded as `FF FF` (signed
    -1) and net-snmp rejected it with "Received bad msgMaxSize
    (18446744073709551615 < 484)". gosnmp tolerated the non-minimal form,
    so only the net-snmp interop test catches it. Pinned by
    `internal/msg/ber_test.go`.
  - **Varbind-list wrap contract**: `BuildPDU`'s varbinds argument is the
    RAW varbind-list content (BuildPDU wraps in the 0x30 SEQUENCE itself);
    `V1TrapToV2` returns raw content for the same reason. Passing an
    already-wrapped list double-wraps it — gosnmp fails with "error
    parsing OID Value: unknown field type: 30". This bug existed in all
    three v1-trap translation paths (translate_manager, tsm_manager,
    gateway) until the gosnmp TrapListener oracle caught it.
  - v3 discovery works unchanged: net-snmp probes with a Reportable
    NoAuthNoPriv GET and accepts our `dropOrReport` Report.
- Test ports must be **ephemeral** (bind `127.0.0.1:0` and read
  `LocalAddr()`): fixed loopback ports flake when the whole suite runs
  with `-race` (packages run in parallel and share the loopback
  namespace). See `fakeAgentOnFreePort` in tsm_e2e_test.go.
- net-snmp TSM client quirks (learned building
  `scripts/interop-gateway-tsm.sh`; painful, documented here so nobody
  re-derives them):
  - Cert fingerprints must be **SHA-256**: net-snmp stores a cert's
    fingerprint using the cert's own signature hash (SHA-256 for our
    EC P-256 PKI), so `clientCert <fp>`/`trustCert <fp>` in snmp.conf
    need `openssl x509 -noout -fingerprint -sha256` values (SHA-1 fps
    never match).
  - Cert dirs are `~/.snmp/tls/{ca-certs,certs,private}` — the CA dir
    is `ca-certs`, NOT `ca`.
  - The `trustCert <fp>` token is required: without it the CA cert
    never reaches the SSL trust store and verification fails with
    "unable to get local issuer certificate".
  - `clientCert <fp>` (deprecated but functional) is what feeds the
    client identity find; `localCert`/`peerCert` do NOT work for this
    in 5.9.4.pre2, and `certSecName` does not exist in that build.
  - Use `dtls:localhost:PORT`, not an IP: net-snmp's server-name check
    only matches DNS SANs ("No matching names in the certificate to
    match the expected 127.0.0.1").
  - Env juggling: `HOME` + `SNMPCONFPATH` both pointed at a temp home;
    `-Ln` silences ALL output including `-D` debug; MIB noise
    ("Cannot find module", "Cannot adopt OID") is harmless.
  - snmptrapd `dtls:` server mode is unusable as an interop sink: its
    main loop never reads the DTLS socket (no sslctx_server invocation
    at all). `scripts/tsm-sink` (raw-DTLS receiver) is used instead.
  - A server cert (EKU serverAuth) presented as a client cert is
    rejected by RequireAndVerifyClientCert sinks with "x509:
    certificate specifies an incompatible key usage" — the gateway's
    trap dialer needs a clientAuth cert if the sink checks EKU.

### pion/dtls v3 quirks (learned the hard way, do not regress)

- **Server-side handshake starts only on first Read/Write of the accepted
  conn.** `listener.Accept()` returns a conn whose handshake FSM is idle;
  the server never answers the ClientHello until the app reads. The proxy
  serves every accepted conn with `NewServerSession` (readLoop) immediately;
  tests must do the same (an "accept and discard" test deadlocks).
- **pion's listener creates a new accepted conn per client UDP port** and
  the client's `dtls.Dial` opens a fresh ephemeral port per attempt. A
  test whose client reconnects (e.g. cipher-suite-mismatch failure then
  backoff retry) must serve EVERY accepted conn in a loop; serving only
  the first one leaves the retried handshake unserved. The client's lazy
  handshake (started inside `Write`, Background ctx) ignores
  `SetWriteDeadline` and waits forever — the write deadline does NOT
  bound the lazy handshake, only the post-handshake record write.
- Client needs BOTH `PSK` and `PSKIdentityHint` set (v3 rejects otherwise).
- **pion/dtls upgraded to v3.1.4 (GO-2026-6165)**: panic parsing a crafted
  ECDHE_PSK ServerKeyExchange in v3.0.10, reachable via our tunnel dialer.
  v3.1.4 replaces the raw `dtls.Config` API with option constructors —
  `dtlsClientOptions`/`dtlsServerOptions` (transport.go/listener.go) build
  `[]dtls.ClientOption`/`[]dtls.ServerOption` and dial/listen via
  `dtls.DialWithOptions`/`dtls.ListenWithOptions`. **Gotcha learned the
  hard way**: `WithPSKIdentityHint` defensively copies the hint and
  `toConfig` drops it when len==0 — an empty PSK identity (`[]byte("")`,
  our config default) silently becomes **nil**, the server then omits the
  ServerKeyExchange entirely, and the client's ClientKeyExchange marshal
  fails (`IdentityHint == nil && PublicKey == nil` → errInvalidClientKeyExchange)
  so the handshake hangs forever. Fix in `dtlsClientOptions`/
  `dtlsServerOptions`: empty identity is replaced with a 1-byte placeholder
  (`[]byte{0}`) so the hint stays non-nil on both sides (v3.0.10 wire
  semantics; the PSK callback ignores the hint value anyway).
- DTLS preserves record boundaries per Read: a partial Read consumes the
  whole record. `streamConn` (internal/tunnel/stream.go) buffers the
  remainder to give io.ReadFull semantics.
- Single `Write` of a multi-frame blob >MTU is silently dropped: the session
  writes each frame separately.
- 13-byte frame headers fail `Unmarshal` (ErrShort) when payload length >0:
  readLoop uses header-only `UnmarshalHeader` then reads the payload.
- **PSK ciphersuite selection** (pion v3.0.10): exactly five PSK suites
  exist — `TLS_PSK_WITH_AES_128_CCM_8` (our default), `AES_256_CCM_8`,
  `AES_128_CCM`, `AES_128_GCM_SHA256`, `AES_128_CBC_SHA256`. A client/
  server suite mismatch fails fast with a fatal alert on both sides —
  but only if the server actually serves the conn (see quirk above).
  Mapping lives in `internal/tunnel/ciphersuite.go`
  (`PskCipherSuiteIDs`, short names + full RFC names as aliases).

## 8. AGENTS.md Maintenance Rule

**Update this file at the end of every task.** Keep §3 status table, §4 layout,
and §7 design notes in sync with reality. Add new decisions to §2. Do not
record aspirational status — only what is actually implemented and tested.
