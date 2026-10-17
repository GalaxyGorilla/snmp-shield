# AGENTS.md — snmp-proxy

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

## 3. Status / Roadmap

**Current state: all four security modes complete — passthrough,
usm-translate (two-proxy tunnel), tsm (two-proxy tunnel), and usm-gateway
(single box, standard v3 in / clear v2c out); no-YAML CLI mode implemented
and smoke-tested end-to-end; cache package unit-tested; net-snmp CLI
interop-tested end-to-end for both the two-proxy chain (incl. trap
direction) and the USM gateway (incl. trap direction and rejection of
clear/wrong-user traffic).**

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
| TSM gateway mode (RFC 6353 SNMP-over-DTLS front leg) | todo (detailed plan below) |
| PSK ciphersuites, notify filtering, HA | backlog |

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
- No-YAML CLI mode: `snmp-proxy gateway --listen :161 --agent
  127.0.0.1:161 --community public --auth-pass <auth> --priv-pass
  <priv> [--trap-listen :162 --trap-sink <mgr>:162]`.
- Tests: `internal/usm/gateway_test.go` (gosnmp v3 authPriv client as
  independent oracle: discovery+GET, wrong-user rejection, clear-v2c
  rejection, trap direction validated by a gosnmp TrapListener);
  `scripts/interop-gateway.sh` drives the gateway with real net-snmp
  v3 clients (snmpget/getnext/bulkwalk/set, wrong-user + clear-v2c
  rejection, snmptrap direction; skips rc 77 without net-snmp).

**2. TSM gateway (`tsm-gateway`)** — RFC 6353 front leg, near-free:

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
  does, Zabbix/PRTG don't) — implement as bonus after USM gateway.

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
cmd/snmp-proxy/           main package; role via subcommand (manager|agent|gateway)
internal/config/          YAML config + flag overrides
internal/proxy/           shared proxy wiring
internal/passthrough/     opaque forwarding of clear SNMP
internal/usm/             USM translate mode + gateway mode + profiles
internal/tsm/             TSM mode
internal/tunnel/          DTLS/TLS tunnel dialer/listener
internal/msg/             SNMP message build/parse helpers
internal/cache/           engine boots/time cache (anti-rollback, persistence)
internal/discovery/       engineID discovery per RFC 3414
internal/securitylevel/   securityLevel constants/validation
internal/observ/          zap logging + Prometheus metrics
```

(Directories with code: config, observ, tunnel, msg, passthrough, proxy,
usm, tsm, cache, cmd/snmp-proxy. Still empty, reserved: discovery
(discovery logic lives in internal/usm translate_manager.go), securitylevel.
Also: configs/ example YAML (manager/agent × psk/usm/tsm + gateway-usm),
scripts/gen-certs.sh throwaway test PKI into gitignored certs/.)

## 5. Build / Test

Go 1.27.2 at `/usr/local/go/bin/go` (on PATH via `/etc/profile.d/go.sh`);
go.mod declares minimum **1.24.0** (CI-free project — tests run manually).

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

**Acceptance for every commit**: build + vet + `go test -race ./...` clean.
Note: non-login shells may not have `go` on PATH — use `/usr/local/go/bin/go`
or set `-timeout` on `go test` (DTLS tests would hang without one).

### No-YAML CLI mode (plug-and-play deployment)

Without `--config`, the subcommands build a validated Config from direct
flags. Two-proxy deployment is two commands plus a generated key:

```bash
KEY=$(snmp-proxy genpsk)   # random 32-byte hex key
snmp-proxy agent   --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass <auth> --priv-pass <priv> --agent 127.0.0.1:161 --community public
snmp-proxy manager --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass <auth> --priv-pass <priv> --listen :161 --community public
```

Flags: `--tunnel-mode` (dtls|tls), `--psk-identity`, `--insecure`,
`--security` (usm-translate|passthrough), `--trap-listen`, `--trap-sink`.
Both sides must share `--psk`/`--auth-pass`/`--priv-pass`. Default security
in flags mode is usm-translate (user 'proxy', SHA, AES).

Gateway (single box, no tunnel/PSK):

```bash
snmp-proxy gateway --listen :161 --agent 127.0.0.1:161 \
  --community public --auth-pass <auth> --priv-pass <priv> \
  [--trap-listen :162 --trap-sink <manager>:162]
```

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

## 6. Key Dependencies (go.mod)

- `github.com/gosnmp/gosnmp` — SNMP v1/v2c/v3 (USM) marshalling, requests
- `github.com/pion/dtls/v3` — DTLS tunnel
- `github.com/prometheus/client_golang` — metrics
- `github.com/spf13/pflag` — CLI flags
- `go.uber.org/zap` — structured logging
- `gopkg.in/yaml.v3` — config parsing

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
  Inbound timeliness per RFC 3414 §3.2 (±150 s window, anti-rollback).
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

### pion/dtls v3 quirks (learned the hard way, do not regress)

- **Server-side handshake starts only on first Read/Write of the accepted
  conn.** `listener.Accept()` returns a conn whose handshake FSM is idle;
  the server never answers the ClientHello until the app reads. The proxy
  serves every accepted conn with `NewServerSession` (readLoop) immediately;
  tests must do the same (an "accept and discard" test deadlocks).
- Client needs BOTH `PSK` and `PSKIdentityHint` set (v3 rejects otherwise).
- DTLS preserves record boundaries per Read: a partial Read consumes the
  whole record. `streamConn` (internal/tunnel/stream.go) buffers the
  remainder to give io.ReadFull semantics.
- Single `Write` of a multi-frame blob >MTU is silently dropped: the session
  writes each frame separately.
- 13-byte frame headers fail `Unmarshal` (ErrShort) when payload length >0:
  readLoop uses header-only `UnmarshalHeader` then reads the payload.

## 8. AGENTS.md Maintenance Rule

**Update this file at the end of every task.** Keep §3 status table, §4 layout,
and §7 design notes in sync with reality. Add new decisions to §2. Do not
record aspirational status — only what is actually implemented and tested.
