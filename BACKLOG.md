# BACKLOG — snmp-shield

The documented protocol scope is implemented. The open items below concern
turnkey integration into a managed appliance with a web UI.

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

## Open — scope

- **S1 Multiple agents per instance:** like the sibling Shield projects,
  snmp-shield binds **one** agent (or manager) target per instance: an
  instance has a single `agent.agent_addr` / `gateway.agent_addr`, and
  `usm-manager-gateway` names one agent user. Protecting several agents means
  one process + config + unit per agent, or one two-proxy pair per endpoint.
  modbus-shield already co-hosts N listener↔device pairs in one process
  (`devices: []`, `internal/proxy/runner.go`): one config, one process, one
  metrics endpoint with a per-device label. Consider the same shape here — one
  instance in front of several agents, each entry a front listener/target with
  its own policy, allow-list and rate limit — so an appliance does not need a
  process per agent. Decide deliberately: this is a scaling/ops convenience,
  **not** a new security capability, and it must not become protocol
  translation or request routing between agents.

  **Confirmed shape (review of the three projects):** the 1-to-1 limit is on
  the *upstream target*, not on clients. A single instance serves any number
  of managers and trap senders; they all reach the one agent. The other
  listeners and lists are not multi-agent:

  - `gateway.listen_addr` (requests) and `gateway.trap_listen_addr`
    (notifications) are different directions/roles, not two front doors for
    one target. The same is true for `manager.*` and `agent.*`.
  - `tunnel.dial_addrs` is a **failover list for the same logical agent-side
    tunnel**, not a set of different agents. It walks the list; it never routes
    a request to a different agent.
  - `security.users` / `security.tsm_identities` are several managers'
    credentials for the **same** agent, not agent selectors.
  - There is no `extra_listen` equivalent: the same request path cannot be
    bound on a second address in one instance.

  Current parity:

  | Capability | modbus-shield | bacnet-shield | snmp-shield |
  |---|---|---|---|
  | Upstream targets per instance | N (`devices:`) | N (`devices:`) | **1** |
  | Front listeners per target | 1 + `extra_listen` | 1 + `extra_listen` | 1 per role/direction; no extras |
  | Per-target policy/metrics | yes | yes | N/A (one target) |

  If S1 is implemented, decide the entry name (`agents:` is more honest than
  `devices:` for SNMP), whether each entry gets its own request + trap
  listeners, and whether an `extra_listen`-style list is needed at all. The
  reference implementations are modbus-shield's `devices:` +
  `internal/proxy/runner.go` and bacnet-shield's `devices:` + `extra_listen`.
