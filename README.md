# snmp-shield

[![Go Reference](https://pkg.go.dev/badge/github.com/GalaxyGorilla/snmp-shield.svg)](https://pkg.go.dev/github.com/GalaxyGorilla/snmp-shield)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A **SNMP securing proxy** for legacy networks. One static binary; three
shapes of deployment: two proxies around a secured line, or a single
gateway box in front of an agent or a manager. End devices keep speaking
plain SNMP; the proxy does all the security work.

```
                 clear SNMP (v1/v2c/v3)           secured segment (v3)            clear SNMP (v1/v2c)
  ┌─────────┐   ─────────────────────►   ┌───────────────────────────┐   ────────────────────►   ┌─────────┐
  │ manager │                            │  proxy A ═══════ proxy B  │                           │  agent  │
  └─────────┘   ◄─────────────────────   └───────────────────────────┘   ◄────────────────────   └─────────┘
                 responses                        (D)TLS over IP                 traps → manager
```

## Why

Legacy devices often can't do SNMPv3 — weak CPUs, ancient firmware, no
budget for an upgrade. snmp-shield keeps those devices untouched while
still getting authentication and encryption where it matters:

- **Zero-touch on end devices** — they keep speaking v1/v2c; the proxy
  does all the security work.
- **One box is enough** — the gateway modes secure a single leg
  (in front of the agent *or* the manager) with standard SNMPv3 or
  SNMP-over-DTLS on the front; the agent-leg gateway also has a
  notification-only shape for manager legs, with informs confirmed
  end-to-end.
- **Standard SNMP at deployment boundaries** — gateway front legs use
  standard SNMPv3 or SNMP-over-DTLS; two-proxy deployments use a
  snmp-shield framed (D)TLS tunnel on their secured segment. This keeps
  endpoint-facing traffic friendly to firewalls, ALGs, DPI and auditors.
- **Deploy by paste** — `genpsk`, two commands, done (see
  [examples/](examples/)).

## Is snmp-shield the right tool?

Not always. Prefer the simplest security boundary that solves the
problem:

- **Devices support SNMPv3** — configure native SNMPv3 USM directly.
  A proxy adds no security benefit to a device that can already
  authenticate and encrypt its own traffic.
- **Only the network path needs protection** — a site-to-site VPN such
  as WireGuard or IPsec may be simpler.
- **You need a flexible, programmable SNMP router or translator** —
  [SNMP Proxy Forwarder (`snmpfwd`)](https://github.com/etingof/snmpfwd/)
  is an established open-source alternative with broad routing and
  plugin capabilities.

Use snmp-shield when legacy v1/v2c devices cannot change and you need
an appliance-like security boundary: standard SNMPv3 USM or
SNMP-over-DTLS at a gateway, or a PSK-DTLS/TLS two-proxy tunnel between
sites. It is intentionally opinionated about deployment and operations:
static binaries, hardened systemd units, configuration validation and
self-tests, tunnel failover, persistent USM engine state, Prometheus
and SNMP health metrics, and SBOM/vulnerability tooling.

## Deployment shapes

| Shape | Topology | Use when |
|---|---|---|
| [Two-proxy USM](examples/two-proxy-usm.md) / [TSM](examples/two-proxy-tsm.md) | `[manager] ⇄ proxy ⇄ secured line ⇄ proxy ⇄ [agent]` | You control both ends; choose USM passphrases or TSM certificates |
| [Gateway (agent side) USM](examples/gateway-usm.md) / [TSM](examples/gateway-tsm.md) | `[v3 managers] ⇄ gateway ⇄ clear ⇄ [legacy agent]` | One box; the **agent** is the asset to protect (usm-gateway; tsm-gateway = RFC 6353 DTLS front leg with certificate clients) |
| [Gateway (manager side) USM](examples/manager-gateway.md) | `[legacy manager] ⇄ clear ⇄ gateway ⇄ v3 authPriv ⇄ [real v3 agent]` | One box; the **agent** is v3-capable but the manager is not — requests are re-issued as authenticated v3 toward the agent (usm-manager-gateway) |
| [Gateway (notifications only) USM](examples/gateway-notifications-only.md) | `[manager] ⇄ v3 ⇄ gateway ⇄ clear ⇄ [legacy devices]` | One box; the **manager** must only accept authenticated notifications (usm-gateway, notification-only — traps/informs, no polling path) |
| [HA two-proxy](examples/ha-two-proxy.md) | Two-proxy + redundant agent side | Failover matters |

## Security modes

**Naming note:** in this project `TSM` always means SNMP's **Transport
Security Model** (RFC 5591) — logging in with a certificate instead of a
passphrase. It has nothing to do with **Time-Sensitive Networking**
(IEEE 802.1, usually abbreviated *TSN*); the acronyms are close enough that
the mix-up has already happened once at planning time.

| Mode | How it works | Use when |
|---|---|---|
| `passthrough` | Opaque forwarding of clear SNMP (v1/v2c/v3). v3 USM params forwarded byte-exact, never decrypted. | Managers/agents already speak SNMPv3; you only need to protect the long-haul link. |
| `usm-translate` | The proxies upgrade the secured segment to **SNMPv3 authPriv** (SHA auth + AES privacy). The agent-side proxy is the authoritative engine: RFC 3414 discovery, engineBoots/engineTime tracking with persistence and anti-rollback, replay window. End devices stay on v1/v2c. | End devices **can't** do SNMPv3. |
| `tsm` | Two role-specific translators protect clear v1/v2c traffic through a certificate-authenticated (D)TLS tunnel. Per RFC 5591, the tunnel handshake **is** the authentication: the peer certificate CN becomes the securityName (allow-listed on the agent side). No USM passphrases, user database or engine state are used — the certificate layer carries all of the security. | You control both proxies and prefer certificates over PSKs/passphrases. |
| `usm-gateway` | Single box; plain-UDP front leg terminates **standard SNMPv3 USM** from any manager (net-snmp, Zabbix, PRTG…). The gateway is the authoritative engine; authenticated requests are relayed as clear v2c to the legacy agent. Clear traffic on the front leg is rejected — that is the protection. Also supports **notification-only** deployments (no request path): clear device traps/informs are wrapped into authenticated v3 USM notifications toward the manager's trap receiver, informs confirmed end-to-end. | The agent is the asset; managers speak standard v3. |
| `tsm-gateway` | Single box; raw DTLS front leg speaks **SNMP-over-DTLS (RFC 6353)**: the client certificate is the authentication (identity allow-list via `security.tsm_identities`). Authenticated requests are relayed as clear v2c to the legacy agent; certificates from untrusted CAs are rejected — that is the protection. Traps and informs relay in both directions with confirmations, same as `usm-gateway`. | Your clients are net-snmp-based with certs (almost no other manager speaks TSM). |
| `usm-manager-gateway` | Single box; the **reverse** of `usm-gateway`: a legacy v2c manager polls the clear front leg and the gateway re-issues every request as **standard SNMPv3 USM authPriv** toward a real v3-capable agent (`--user` names the agent's configured user). RFC 3414 engine discovery against the agent, responses verified + decrypted before they are stripped back to clear v2c. Agent traps/informs are verified, unwrapped and relayed as clear v2c to the manager's trap receiver (informs confirmed by the gateway). v3 on the clear front leg is ignored — that is the protection. | The agent speaks v3 but the manager is legacy — upgrade the proxy→agent wire without touching the manager. |

All two-proxy modes carry the full operation set in both directions:
`GET`, `GETNEXT`, `SET`, `GETBULK`, plus **traps and informs** both ways
(inform confirmations relayed end-to-end). Gateway modes confirm informs
the same way: the manager's acknowledgment flows back through the
gateway to the device in every gateway mode.

**About the "v3" labels**: SNMPv3 alone is not a security guarantee —
RFC 3414 defines three security levels, and only **authPriv** (digest
authentication + encryption) secures the wire. Rows labeled `v3
authPriv` enforce that level. Rows labeled plain `v3` (usm-gateway and
its notification-only shape) inherit the level from the configured
users in `security.users` — every shipped default is SHA + AES
(authPriv), but a user configured with `auth_protocol: none` would
speak noAuthNoPriv v3 (framed, not secured). Configure real passphrases
and the leg is authPriv.

**Why TSM is not everywhere**: TSM — the Transport Security Model, RFC 5591 —
exists in exactly two shapes here — the two-proxy tunnel and the agent-side
gateway front leg
(`tsm-gateway`). There is no TSM variant of the manager-side gateway,
and TSM gateway support is a niche option rather than the default:

- **Almost no manager speaks TSM.** SNMP-over-(D)TLS (RFC 6353) is
  implemented by net-snmp; mainstream management platforms (Zabbix,
  PRTG, …) speak USM v3. The USM gateway is the front door for those.
- **TSM-capable devices virtually always speak USM too.** A device that
  terminates SNMP-over-DTLS is by definition modern and v3-capable, so
  the manager-side gateway for such devices already exists as
  `usm-manager-gateway` (the industry-standard USM path, interop-tested
  against real snmpd).
- **Server-side TSM stacks are rare and incomplete.** Net-snmp's
  server-side DTLS support is partial; there is no realistic population
  of TSM-only agents to point a TSM variant of the manager-side gateway
  at.

Practical rule: certificates are the *tunnel* authentication between two
snmp-shield proxies (any endpoints, any SNMP versions); USM is the
*endpoint* security toward managers and agents, which everything
industry-standard speaks.

## Access control

Every deployment has a request leg with a peer you may or may not trust, so
the same `access` section exists on all three roles: **who** may talk to
the proxy, **how fast**, and **what may be written**.

```yaml
access:
  allow: ["10.8.0.0/24", "192.168.1.5"]   # client allow-list (IP or CIDR)
  rate_per_sec: 50                        # per-client request rate (0 = unlimited)
  read_only: true                         # refuse every SET
  # …or, instead of read_only, a scope-limited write policy:
  # write_policy:
  #   default: deny
  #   rules:
  #     - {oid: "1.3.6.1.4.1.99.1",     action: allow}
  #     - {oid: "1.3.6.1.4.1.99.1.9",   action: deny}
```

`read_only` and `write_policy` are mutually exclusive; `rate_per_sec` and
`allow` are independent and optional. In flags mode: `--allow` (repeatable),
`--rate-per-sec`, `--read-only`, or `--write-default deny --write-allow
<oid> --write-deny <oid>`.

**Where each part applies** — the policy follows the client address:

| Role | `allow` / `rate_per_sec` | `read_only` / `write_policy` |
|---|---|---|
| `manager` (clear manager leg) | yes | yes |
| `gateway` (USM or TSM front leg) | yes | yes |
| `agent` (tunnel ingress, device-facing box) | no — requests carry no client address (warned at startup) | yes — defense in depth: the box next to the device refuses writes itself, even if the manager side is compromised |
| any role, `security.mode: passthrough` | yes | v1/v2c only — v3 crosses the tunnel opaquely (warned at startup) |

**What happens on a denial** — the cases are deliberately different:

| Denial | Behaviour | Why |
|---|---|---|
| Client not on `allow` | **Silent drop** | An off-list peer must not learn a proxy is there, and an error answer would amplify a flood. |
| Client over `rate_per_sec` | **Silent drop** | Same reasoning: the limit exists to absorb a flood, not to chat with it. |
| SET outside the write policy | **Answered** (`notWritable`, v1: `noSuchName`) | The peer is authenticated and legitimate; a timeout would only make it retransmit into the policy forever. |

Write-policy evaluation is **deny-overrides, allow-must-cover**, and rules
are evaluated as a *set* (order is irrelevant):

- any matching **deny** rejects the entire SET — one forbidden object in a
  multi-varbind SET is enough (a write can never straddle the boundary);
- an **allow** only wins when a single rule covers **every** requested
  object;
- otherwise `default` applies (`deny` unless configured `allow`).

Matching is prefix-based on OID arc boundaries (`1.3.6.1.4.1.99` matches
`…99.5` but not `…9999`). A SET whose varbinds cannot be decoded is denied —
an unparseable write cannot be authorized. Non-SET PDUs always pass; reads
are governed by the allow-list and rate limit, not by the write policy.

**Passthrough caveat**: `passthrough` forwards SNMPv3 opaquely, so a v3 SET
cannot be inspected. `write_policy`/`read_only` therefore govern v1/v2c
only there (on the agent side they cannot see tunnel traffic at all); the
proxy warns at startup if you configure this combination. Notify filtering
is unaffected (notifications are inspected on their clear legs in every
mode).

**Reload**: `SIGHUP` re-reads the YAML file and applies **the access policy
only** — the part you change during an incident (cut off a noisy client,
lock a write path). It is read per datagram, so the swap takes effect on
the next packet with no listener rebind. Everything socket- or
crypto-bound (tunnel, security/users, listeners, notification filters,
metrics endpoints) is logged as `(restart required)` rather than silently
ignored. An invalid file, or a policy that does not compile, keeps the
running policy: a reload typo must never leave the proxy unprotected or
wide open.

## Tunnel transport

- **DTLS over UDP** (primary) — preserves SNMP's connectionless model.
- **TLS over TCP** (alternative) — `--tunnel-mode tls`.
- **HA failover** — the manager side dials a list of endpoints
  (`tunnel.dial_addrs`), detects dead peers via keepalive (3 missed
  probes at 3× the keepalive interval), and reconnects automatically.
  Redundant replicas share one engine identity and converge their engine
  state — managers never re-discover.

The secured segment is application-layer crypto over any IP network; the
proxies don't care what's underneath. Configuration is just `ip:port`
endpoints.

## Quick start

Build (plain Go, no dependencies to install beyond the toolchain):

```bash
make            # or: go build -o bin/snmp-shield ./cmd/snmp-shield
```

### Plug and play (no config files)

```bash
KEY=$(./bin/snmp-shield genpsk)   # random 32-byte hex key

# agent-side box (faces the real agent)
./bin/snmp-shield agent --tunnel-addr <agent-box-ip>:19611 --psk $KEY \
  --auth-pass myauthpass --priv-pass myprivpass \
  --agent 127.0.0.1:161 --community public

# manager-side box (faces the monitoring station)
./bin/snmp-shield manager --tunnel-addr <agent-box-ip>:19611 --psk $KEY \
  --auth-pass myauthpass --priv-pass myprivpass \
  --listen :161 --community public
```

Point the manager at the manager-side proxy instead of the agent, and
point device traps at the proxy's `--trap-listen` instead of the
manager. Both sides share `--psk`, `--auth-pass` and `--priv-pass`.

Full walkthroughs for every deployment shape: [examples/](examples/).

### Single-box gateway

```bash
./bin/snmp-shield gateway --security usm-gateway \
  --listen :161 --agent 127.0.0.1:161 \
  --auth-pass myauthpass --priv-pass myprivpass
```

Any standard v3 manager now polls the gateway with user `proxy`
(SHA/AES) and the legacy agent never sees unauthenticated traffic.

Notification-only variant (protects the manager leg: clear device
traps/informs in, authenticated v3 toward the manager's trap receiver,
informs confirmed end-to-end — no request path):

```bash
./bin/snmp-shield gateway --security usm-gateway \
  --trap-listen :162 --trap-sink <manager-ip>:162 \
  --auth-pass myauthpass --priv-pass myprivpass
```

Reverse direction (legacy v2c manager in front, real v3-capable agent
behind — requests re-issued as authenticated v3 toward the agent):

```bash
./bin/snmp-shield gateway --security usm-manager-gateway \
  --listen :161 --agent <v3-agent-ip>:161 \
  --user authPrivUser \
  --auth-pass agents-auth-pass --priv-pass agents-priv-pass
```

A legacy v2c manager polls the gateway with any community; the gateway
performs RFC 3414 engine discovery against the real agent and re-issues
each request signed and encrypted. Agent traps/informs arrive verified
at the gateway's `--trap-listen` and are relayed as clear v2c to the
manager's `--trap-sink`.

### Config files

Each instance is one YAML file; the role is chosen by the subcommand.
Templates for every combination live in [`configs/`](configs/):

```bash
./bin/snmp-shield manager --config configs/manager-usm.yaml
./bin/snmp-shield agent   --config configs/agent-usm.yaml
./bin/snmp-shield gateway --config configs/gateway-usm.yaml
./bin/snmp-shield gateway --config configs/gateway-manager-gateway.yaml
```

## Tools

```bash
# validate a config without running (pre-apply hook for tooling/web UIs;
# --json for machine-readable output):
snmp-shield validate --role gateway --config /etc/snmp-shield/gateway.yaml

# validate + probe the environment (cert expiry, engine store, tunnel
# handshake, SNMP GET to the real agent; --probe=false skips network):
snmp-shield selftest --role gateway --config /etc/snmp-shield/gateway.yaml

# other commands:
snmp-shield genpsk     # fresh random pre-shared key
snmp-shield version
```

Both `validate` and `selftest` accept the same flags as the role
subcommands (or `--config`), so a web UI can build the form, validate
with `validate --json`, and offer a "test connection" button backed by
`selftest --json`.

## Appliance deployment

- **Static binary** — `make release` produces a stripped, cgo-free
  static binary suitable for any Linux appliance (musl/glibc-free).
- **Cross-builds** — `make release-all` produces stripped static binaries
  for all appliance platforms into `dist/`: `linux-amd64`, `linux-arm64`,
  `linux-armv7`. Pure Go with CGO disabled — cross-compiling is exact.
- **systemd units** — [`deploy/`](deploy/) ships hardened unit files
  (`Type=notify`, `WatchdogSec=30`, Restart=on-failure,
  `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE`
  for privileged ports, persistent `StateDirectory` for the engine
  boots store, and `ExecReload=/bin/kill -HUP $MAINPID` for
  `systemctl reload` → access-policy reload).
- **systemd watchdog** — the binary speaks sd_notify: `READY=1` on
  startup and `WATCHDOG=1` pings while running (internal/watchdog), so a
  wedged process is restarted by the host. No-ops outside systemd.
- **Engine state** — `security.engine_store` must be on persistent
  storage: engineBoots must never decrease (anti-rollback). systemd's
  `StateDirectory=snmp-shield` covers this.
- **Supply chain** — `make sbom` produces SPDX + CycloneDX SBOMs of the
  release binary into `dist/`; `make vulnscan` matches them against
  NVD/GHSA/OSV and fails on HIGH-severity findings. Useful for release
  provenance on the appliance. `scripts/sbom.sh` runs the same flow
  standalone (`--sbom-only` skips the scan).
- **Metrics** — Prometheus endpoint via `--metrics-addr`: tunnel
  frames/bytes, forwarded requests, errors, notifications relayed/
  filtered/dropped, reconnects, tunnel-up gauge, forwarding latency, and
  the access-policy counters (`snmp_shield_acl_denied_total`,
  `snmp_shield_writes_denied_total`, `snmp_shield_rate_limited_total`).
- **SNMP metrics interface** — every role can expose its health over
  SNMP itself: `metrics.listen_addr` (or `--metrics-snmp-listen`)
  serves a small read-only SNMPv2c agent (GET/GETNEXT: identity,
  tunnel state, counters) and `metrics.trap_sink_addr` (or
  `--metrics-snmp-trap-sink`) emits v2c traps on tunnel lifecycle
  changes (up/down, HA failover). `metrics.community` (default
  "public") and `metrics.base_oid` apply to both. Prometheus stays
  available alongside.

## Operations

- **Reconnect with backoff** — the manager side dials and reconnects
  automatically (configurable ceiling).
- **Keepalive** — PING/PONG frames keep NAT mappings alive and detect
  dead peers.
- **Graceful shutdown** — SIGINT/SIGTERM closes sockets and loops
  cleanly.
- **Notification filtering** — `notifications.filter` (allow/deny OID
  prefixes, arc-boundary match) drops unwanted notifications at the
  relay ingress; `--filter-oid`/`--filter-action` in flags mode.
- **Access control** — `access.allow` / `access.rate_per_sec` /
  `access.read_only` / `access.write_policy` gate the request leg of
  every role (see [Access control](#access-control)).
- **Config reload** — `SIGHUP` re-reads the YAML file and swaps the
  access policy in place; other blocks are reported as restart-only.
- **Engine state persistence** — engineBoots persisted to disk;
  timeliness enforced per RFC 3414 §3.2 (±150 s window).

## Building and testing

```bash
make build       # bin/snmp-shield
make test        # gofmt gate + go test ./... -race -timeout 180s
make vet         # go vet ./...
make release     # stripped static binary for deployment
make release-all # cross-builds: linux-amd64, linux-arm64, linux-armv7 into dist/
make peers       # provision the third-party stacks for the conformance matrix
make conformance # cross-vendor matrix: net-snmp, pysnmp, node net-snmp, gosnmp
make interop     # net-snmp CLI interop test (exit 77 = skip when missing)
make sbom        # SPDX + CycloneDX SBOMs for the release binary (syft) into dist/
make vulnscan    # match the SBOM against NVD/GHSA/OSV; fails on HIGH+ (grype)
```

Every commit is expected to pass build + vet + the race suite (run
manually; the project is CI-free). `make conformance` additionally drives
the built binary with independent SNMP implementations, so a bug in our own
encoder cannot hide behind a matching decoder; see
[`CONFORMANCE.md`](CONFORMANCE.md) and [`TESTING.md`](TESTING.md).
`make vulnscan` also runs `scripts/sbom.sh`-style supply-chain checks
standalone; both targets
exit 77 (skip) when syft/grype are not installed.

## Documentation

- [`examples/`](examples/) — copy-paste walkthroughs for every
  deployment shape.
- [`configs/`](configs/) — YAML templates for every mode.
- [`deploy/`](deploy/) — systemd unit files.
- [`AGENTS.md`](AGENTS.md) — architecture, wire-level quirks
  (pion/dtls, gosnmp, net-snmp, BER) and the maintenance rules.
- [`docs/security-hardening.md`](docs/security-hardening.md) — review
  notes for the security-level and access-policy hardening: what was
  broken, what fixed it, and what was deliberately left out.

## License

[MIT](LICENSE)
