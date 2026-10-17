# snmp-proxy

[![Go Reference](https://pkg.go.dev/badge/github.com/GalaxyGorilla/snmp-proxy.svg)](https://pkg.go.dev/github.com/GalaxyGorilla/snmp-proxy)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Tests](https://img.shields.io/badge/tests-go_test_-race-brightgreen.svg)

A **SNMP securing proxy**. One binary, two instances, one per entity: each
instance secures its local clear SNMP leg and encrypts the long-haul
segment between them.

```
                 clear SNMP (v2c/v3)              secured segment                clear SNMP (v2c)
  ┌─────────┐   ─────────────────────►   ┌───────────────────────────┐   ────────────────────►   ┌─────────┐
  │ manager │                            │  proxy A ═══════ proxy B  │                           │  agent  │
  └─────────┘   ◄─────────────────────   └───────────────────────────┘   ◄────────────────────   └─────────┘
                 responses                        (D)TLS over IP                 traps → manager
```

Plug the proxies in between an SNMP manager and an SNMP agent without
changing either: end devices keep speaking plain v2c/v3, and the proxies
secure the line in between.

## Why

Legacy devices often can't do SNMPv3 — weak CPUs, ancient firmware, no
budget for an upgrade. snmp-proxy lets you keep those devices untouched
while still getting authenticated, encrypted transport between networks:

- **Zero-touch on end devices** — they keep speaking v2c; the proxies do
  all the security work.
- **End-to-end v3 stays byte-exact** — in passthrough mode, v3 USM
  parameters are forwarded untouched so manager↔agent engine verification
  still works; the proxy never needs to decrypt.
- **Deploy by paste** — same key on both proxies, two commands, done.

## Security modes

| Mode | How it works | Use when |
|---|---|---|
| `passthrough` | Opaque forwarding of clear SNMP (v1/v2c/v3). v3 USM params forwarded byte-exact, never decrypted. | Managers/agents already speak SNMPv3; you only need to protect the long-haul link. |
| `usm-translate` | Proxies upgrade the long-haul to **SNMPv3 authPriv** (SHA auth + AES privacy by default). The agent-side proxy is the authoritative engine: RFC 3414 engine discovery, engineBoots/engineTime tracking with persistence and anti-rollback, replay window. End devices stay on v1/v2c. | End devices **can't** do SNMPv3 (hardware constraints, legacy firmware). |
| `tsm` | RFC 5591: the tunnel (D)TLS handshake *is* the SNMP authentication. Peer certificate (leaf CN) becomes the securityName; allow-list identities on the agent side. | You prefer certificate-based auth over PSKs/passphrases. |

All modes carry the full operation set in both directions:
`GET`, `GETNEXT`, `SET`, `GETBULK` (downgraded to `GETNEXT` on v1), plus
**traps and informs** both ways.

## Tunnel transport

- **DTLS over UDP** (primary) — preserves SNMP's connectionless model.
- **TLS over TCP** (alternative) — `--tunnel-mode tls`.

The secured segment is plain application-layer crypto over any IP network
— the proxies don't care what's underneath. Configuration is just
`ip:port` dial/listen endpoints.

## Quick start

Install Go 1.21+, then:

```bash
git clone https://github.com/GalaxyGorilla/snmp-proxy
cd snmp-proxy
go build ./cmd/snmp-proxy
```

### Plug and play (no config files)

```bash
KEY=$(./snmp-proxy genpsk)   # random 32-byte hex key

# agent-side proxy device (faces the real device)
./snmp-proxy agent --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass myauth --priv-pass mypriv \
  --agent 127.0.0.1:161 --community public

# manager-side proxy device (faces the monitoring station)
./snmp-proxy manager --tunnel-addr <manager-proxy-ip>:19611 --psk $KEY \
  --auth-pass myauth --priv-pass mypriv \
  --listen :161 --community public
```

Point the manager at the manager-side proxy instead of the agent, and
point device traps at the agent-side proxy instead of the manager. Both
sides must share `--psk`, `--auth-pass` and `--priv-pass`.

### Config files

Each instance is described by one YAML file; the role is chosen by the
subcommand. Templates for every combination live in [`configs/`](configs/):

```bash
./snmp-proxy manager --config configs/manager-usm.yaml
./snmp-proxy agent   --config configs/agent-usm.yaml
```

For `tsm` mode, generate a test PKI with
[`scripts/gen-certs.sh`](scripts/gen-certs.sh) (writes into `certs/`,
gitignored).

### Smoke test

End-to-end verification on a single host (no DTLS quirks, no external
tools):

```bash
./scripts/smoke-cli.sh   # exit 0 = green
```

It builds the binary, starts both proxies via flags plus a fake Python
v2c agent, and polls through the whole secured chain with a gosnmp
client.

## Operations

- **Metrics** — Prometheus endpoint via `--metrics-addr 127.0.0.1:9672`:
  tunnel frames/bytes, forwarded requests, errors, notifications relayed,
  drops, reconnects, tunnel-up gauge, forwarding latency histogram.
- **Reconnect with backoff** — the manager side dials and reconnects
  automatically (exponential backoff, configurable ceiling).
- **Keepalive** — PING/PONG frames keep NAT mappings alive and detect
  dead peers.
- **Graceful shutdown** — SIGINT/SIGTERM closes sockets and loops cleanly.
- **Engine state persistence** — engineBoots is persisted to disk
  (`security.engine_store`); boots must never decrease (anti-rollback),
  and inbound timeliness is enforced per RFC 3414 §3.2 (±150 s window).

## Repository layout

```
cmd/snmp-proxy/     main package; subcommands manager|agent|genpsk|version
internal/config/    YAML config + flag overrides, validation
internal/proxy/     role wiring, shutdown, metrics serving
internal/passthrough/ opaque forwarding of clear SNMP
internal/usm/       USM translate mode + profiles + crypto
internal/tsm/       TSM mode (RFC 5591)
internal/tunnel/    DTLS/TLS transport, framing, sessions
internal/msg/       SNMP BER build/parse helpers
internal/cache/     engine boots/time store (persistence)
internal/observ/    zap logging + Prometheus metrics
```

## Building and testing

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

Every commit is expected to pass all three (run them manually before pushing).

## Status & roadmap

Implemented and tested:

- Config package (YAML + flags, both roles)
- Logging/metrics baseline (zap + Prometheus)
- Tunnel: DTLS/UDP + TLS/TCP dialer/listener, framing, sessions
- Passthrough forwarding (v1/v2c/v3, traps/informs)
- USM translate mode (engineID discovery, boots/time cache, interop-tested
  byte-exact against gosnmp v3 authPriv clients)
- TSM mode (RFC 5591)
- No-YAML CLI mode + smoke-test harness

Backlog: additional PSK ciphersuites, notification filtering, high
availability, net-snmp CLI interop tests.

## Design notes

- **Passthrough mode never decrypts.** v3 messages are forwarded with USM
  parameters byte-exact so end-to-end engineID/boot/time verification
  between the real manager and agent keeps working.
- **USM translate owns the v3 machinery.** The agent-side proxy answers
  discovery (empty Reportable NoAuthNoPriv GET → Report PDU with its
  engineID/boots/time), enforces timeliness windows, and converts v1/v2c ↔
  v3 in both directions. Translation is PDU splicing — the proxy never
  parses varbinds it doesn't need to touch.
- **TSM makes the handshake the authentication.** The tunnel's (D)TLS
  peer certificate maps to a securityName; no SNMP-level credentials ride
  the clear legs.
- **Traps flow both directions**: devices → agent-side proxy → tunnel →
  manager-side proxy → real manager (and the reverse for manager-originated
  notifications).

For agent-facing contributors, [`AGENTS.md`](AGENTS.md) documents the
architecture, hard-won quirks (pion/dtls handshake behavior, gosnmp
encoding details, BER pitfalls) and the maintenance rules.

## License

[MIT](LICENSE)
