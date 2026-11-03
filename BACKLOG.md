# BACKLOG — snmp-shield

The documented protocol scope is implemented. The open items below concern
turnkey integration into a managed appliance with a web UI. The gateway
multi-agent co-hosting (S1a) is implemented; the two-proxy variant stays
closed.

## Open — appliance management integration

- **A1 Versioned configuration schema:** expose a stable JSON Schema for every
  role, mode, YAML field, default, constraint, conditional field, description,
  secret, and restart/reload behavior. Generate or test it against the Go
  configuration types so UI forms cannot silently drift from the daemon.
- **A2 Restricted local management API:** provide a Unix-socket interface (or a
  small shared management sidecar) for validate, self-test, apply, reload,
  restart, status, and rollback. The web process must not run arbitrary shell
  commands or require unrestricted root access. Keep the SNMP data plane
  independent from the management plane.
- **A3 Transactional configuration:** stage a revision, run `validate --json`
  and optional `selftest --json`, install it atomically, reload or restart as
  required, verify health, and automatically restore the previous known-good
  revision on failure. Preserve an auditable revision history.
- **A4 Unified structured status:** expose the active configuration revision
  and hash, role and mode, readiness, tunnel and peer state, reload result,
  restart-required fields, engine-store health, certificate expiry, and
  relevant counters as stable JSON. Never include communities, USM secrets,
  PSKs, or private-key material.
- **A5 Secret, certificate, and engine-state lifecycle:** define safe upload,
  ownership, permissions, validation, rotation, expiry reporting, backup,
  anti-rollback handling, and redaction behavior. Encryption at rest and
  master-key custody belong to the appliance layer, not the protocol daemon.
- **A6 Appliance-level acceptance tests:** exercise the complete web UI/API →
  staged YAML → validation/self-test → systemd reload/restart → real SNMP
  request and notification path. Cover every supported role, invalid
  configuration, interrupted apply, failed self-test, rollback, secret
  rotation, engine-state persistence, power loss, and all supported appliance
  architectures.

Completion means an unprivileged management UI can safely configure and
operate every supported deployment mode without duplicating undocumented
daemon behavior.

## Done — scope (kept for reference)

- **S1a Multiple agents per instance (gateway-only) — DONE (Phase 1 +
  Phase 2 core, 2026-11-03).** The gateway role now accepts an `agents:` list: one
  process, one config, one metrics endpoint, N independent
  listener↔agent pairs. Each entry has its own `access`, `security`
  (users, engine ID/store, TSM identities, trap community), optional
  `tls`, optional trap legs and optional notification filter.
  `security.engine_store_dir` derives a per-entry store as
  `<dir>/<name>.json`; an explicit `engine_store` wins. One security mode
  per process. TSM front sessions share one process-wide
  `tunnel.max_sessions` budget. SIGHUP applies access changes per entry by
  name; listener/agent/security/TLS/notifications/trap changes are
  restart-required. `validate`/`selftest` iterate entries, Prometheus
  counters carry an `agent` label (single-target roles use
  `agent="default"`), the SNMP health MIB exposes a per-agent `.40.<n>`
  table, and `/status` on the metrics listener exposes per-entry
  endpoints/policy/counters as JSON. Design and implementation notes:
  [docs/multi-agent.md](docs/multi-agent.md). Tests: two-entry USM e2e
  (independent policies, no cross-entry traffic, per-agent metrics),
  per-entry trap delivery/filtering, SIGHUP access reload,
  TSM/manager-gateway bind smoke tests, config validation, per-entry
  selftest, MIB table GET/GETNEXT, two-entry USM conformance across all
  available peers, two-entry TSM vendor-client conformance over DTLS, a
  fast multi-agent goroutine regression, and a soak-gated multi-agent
  steady-state test (`TestSoakMultiAgentSteadyState`).

  The two-proxy shape stays one pair per agent: the custom tunnel frame has
  no agent selector, and adding one would turn the security tunnel into a
  router. That part is closed as **S1b** below.

## Closed — scope (kept for reference)

- **S1b Multi-agent over the two-proxy tunnel — CLOSED (not planned).**
  The 1-to-1 limit is on the *upstream target*, not on clients. A single
  instance serves any number of managers and trap senders; they all reach
  the one agent. The other listeners and lists are not multi-agent:

  - `gateway.listen_addr` (requests) and `gateway.trap_listen_addr`
    (notifications) are different directions/roles, not two front doors for
    one target. The same is true for `manager.*` and `agent.*`.
  - `tunnel.dial_addrs` is a **failover list for the same logical agent-side
    tunnel**, not a set of different agents. It walks the list; it never
    routes a request to a different agent.
  - `security.users` / `security.tsm_identities` are several managers'
    credentials for the **same** agent, not agent selectors.
  - There is no `extra_listen` equivalent: the same request path cannot be
    bound on a second address in one instance.

  **Why S1b is closed:** SNMP has no honest target selector in the request
  (community and `contextName` are security identities; the translating modes
  drop `contextName`), so a shared front listener would be a proxy forwarder.
  The tunnel frame has no agent selector either. USM/TSM state is per agent,
  so multi-agent over one tunnel would need both routing and per-agent
  security inside the custom link. One pair per agent is the honest shape.

  Current parity:

  | Capability | modbus-shield | bacnet-shield | snmp-shield |
  |---|---|---|---|
  | Upstream targets per instance | N (`devices:`) | N (`devices:`) | gateway: N (implemented); two-proxy: 1 |
  | Front listeners per target | 1 + `extra_listen` | 1 + `extra_listen` | 1 per target; no extras |
  | Per-target policy/metrics | yes | yes | per entry |
  | Model | co-hosting | co-hosting | gateway co-hosting; two-proxy one pair per target |

  The sibling reference implementations are modbus-shield's `devices:` +
  `internal/proxy/runner.go` and bacnet-shield's `devices:` + `extra_listen`.
  They remain the right reference for what co-hosting means.

## Done — testing (kept for reference)

- **Soak coverage:** `make soak` (opt-in, 10 min per test) covers the
  two-proxy steady state, HA failover under load, the spoofed-source
  rate-limit flood, and the multi-agent gateway
  (`TestSoakMultiAgentSteadyState`: two `agents:` entries under continuous
  v3 request load plus periodic per-entry trap traffic to both sinks — zero
  unanswered requests, flat goroutines, bounded live heap).
  A 20s quick pass is green (1,850 requests, goroutines 11 → 11, live heap
  1.0 → 1.1 MiB); the full 10-minute run is a release-checklist item. The
  fast non-soak net for the goroutine class is
  `TestGatewayAgentsNoPerRequestGoroutines`.
