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
| [Gateway (agent side)](examples/gateway-usm.md) | `[v3 managers] ⇄ gateway ⇄ clear ⇄ [legacy agent]` | One box; the **agent** is the asset to protect (usm-gateway) |
| [Gateway (manager side)](examples/manager-gateway.md) | `[legacy manager] ⇄ clear ⇄ gateway ⇄ v3 authPriv ⇄ [real v3 agent]` | One box; the **agent** is v3-capable but the manager is not — requests are re-issued as authenticated v3 toward the agent (usm-manager-gateway) |
| [Gateway (notifications only)](examples/usm-manager.md) | `[manager] ⇄ v3 ⇄ gateway ⇄ clear ⇄ [legacy devices]` | One box; the **manager** must only accept authenticated notifications (usm-gateway, notification-only — traps/informs, no polling path) |
| [HA two-proxy](examples/ha-two-proxy.md) | Two-proxy + redundant agent side | Failover matters |

## Security modes

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
- **systemd units** — [`deploy/`](deploy/) ships hardened unit files
  (Restart=on-failure, `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE`
  for privileged ports, persistent `StateDirectory` for the engine
  boots store).
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
  filtered/dropped, reconnects, tunnel-up gauge, forwarding latency.
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
- **Engine state persistence** — engineBoots persisted to disk;
  timeliness enforced per RFC 3414 §3.2 (±150 s window).

## Building and testing

```bash
make build     # bin/snmp-shield
make test      # go test ./... -race -timeout 180s
make vet       # go vet ./...
make release   # stripped static binary for deployment
make sbom      # SPDX + CycloneDX SBOMs for the release binary (syft) into dist/
make vulnscan  # match the SBOM against NVD/GHSA/OSV; fails on HIGH+ (grype)
```

Every commit is expected to pass build + vet + the race suite (run
manually; the project is CI-free). `make vulnscan` also runs
`scripts/sbom.sh`-style supply-chain checks standalone; both targets
exit 77 (skip) when syft/grype are not installed.

## Documentation

- [`examples/`](examples/) — copy-paste walkthroughs for every
  deployment shape.
- [`configs/`](configs/) — YAML templates for every mode.
- [`deploy/`](deploy/) — systemd unit files.
- [`AGENTS.md`](AGENTS.md) — architecture, wire-level quirks
  (pion/dtls, gosnmp, net-snmp, BER) and the maintenance rules.

## License

[MIT](LICENSE)
