# Multiple agents per instance — gateway-only co-hosting

**Status:** Phase 1 + Phase 2 core implemented (2026-11-03): `agents:`
list for the gateway role, per-entry access/security/TLS/notifications,
per-entry trap legs, per-agent Prometheus labels and SNMP MIB table,
one process-wide TSM session cap, per-entry `validate`/`selftest` and
SIGHUP reload, a `/status` JSON document, and a two-entry conformance
scenario, plus a two-entry TSM vendor-client scenario and a long
multi-agent soak. A shared trap listener remains an optional follow-up
(§11).
**Decision:** only the gateway part of backlog item S1 is implemented.
The two-proxy tunnel stays one pair per agent.

## 1. Why this exists

Modbus-shield and bacnet-shield co-host N listener↔device pairs in one
process (`devices:`). snmp-shield's gateway role currently binds one
upstream agent per process. Running N processes works, but it means N
configs, N units and N metrics endpoints for the same box.

| Protocol | Scaling today | Security today |
|---|---|---|
| Modbus TCP | one process, N listener↔device pairs (`devices:`) | per device: ACL, write policy, TLS/mTLS, mbaps roles |
| BACnet/IP | one process, N listener↔device pairs (`devices:`) | per device: ACL, write policy, SC certs/VMAC |
| SNMP | gateway: **N agents per process** (`agents:`); two-proxy: one agent per process | per agent in the gateway role; process-global in two-proxy |

This document defines the gateway shape that matches the siblings: **one
process, one config, one metrics endpoint, N independent listener↔agent
pairs**. It is a scaling/ops convenience, not a new security capability.

The old S1 was broader and was closed because it mixed two different
things:

- **S1a — gateway co-hosting:** one process in front of several legacy
  agents, each with its own front listener. This is the subject of this
  document.
- **S1b — multi-agent over the two-proxy tunnel:** not natural. The
  custom tunnel frame has no agent selector; adding one would turn the
  security tunnel into a router. S1b stays closed.

## 2. Gateway vs two-proxy, in one table

| | Two-proxy | Gateway |
|---|---|---|
| Boxes | 2 (`manager` + `agent`) | 1 (`gateway`) |
| Wire protocol | custom DTLS/TLS tunnel; standard SNMP inside | standard SNMPv3 USM / TSM / clear v1-v2c |
| Security boundary | between the two shields | at the gateway |
| Endpoints | both unchanged | one side standard-secure, one side legacy |
| Typical use | site-to-site, long-haul, both legacy | one-box retrofit |
| Multi-agent | one pair per agent | **N agents per instance (implemented)** |
| Custom protocol | yes | no |

The gateway is the single-box shape. Co-hosting belongs there. The
two-proxy shape is a link between two sites; for N agents it stays N
pairs.

## 3. Goals

- One process, one config file, one systemd unit, one metrics endpoint
  for N gateway agents.
- Each entry owns:
  - its front listener,
  - its upstream agent,
  - its access policy (allow-list, rate limit, write policy),
  - its name (logs, metrics, status, reload key),
  - optional trap legs.
- No routing: a front listener is bound to exactly one agent. No datagram
  crosses entries.
- Each entry owns its security configuration — USM users and engine
  state, TSM identities and TLS material, access policy — matching the
  sibling per-device model. Top-level blocks are defaults; per-entry
  values win.
- Per-agent status and metrics; per-entry `validate`/`selftest`; SIGHUP
  reload by entry name.
- The existing single-agent config keeps working unchanged.

## 4. Non-goals

- Multi-agent over the two-proxy tunnel (S1b).
- A shared front listener that selects an agent by community, context, or
  OID. That is a proxy forwarder, not a security gate.
- SNMPv3 context multiplexing through the translating modes. The
  translating gateway drops `contextName`; it is not a target selector.
- Heterogeneous `security.mode` per entry. One mode per process is the
  real-world shape: a site standardizes on the side that is legacy or
  secure. Mixed modes are separate instances, not one process.
- Multi-agent in flags mode. YAML only.
- Cross-agent traffic, load balancing, or failover from one agent to
  another.
- A BBMD-like discovery service for SNMP. Managers are explicitly
  configured with a target address.

## 5. Process shape

One process hosts N independent translators. Each entry owns its front
listener, upstream socket, access policy, security state and counters.
They share the binary, config file, log and metrics registry. No datagram
crosses entries. This is co-hosting, not routing.

## 6. Proposed configuration

### 6.1 Shape

Add an `agents:` list to the gateway role. It is mutually exclusive with
the single-agent `gateway.listen_addr` / `gateway.agent_addr` pair.

```yaml
security:
  mode: usm-gateway
  # Process-wide defaults; entries may override.
  engine_store_dir: /var/lib/snmp-shield/engines
  users:
    - name: monitoring
      auth_protocol: SHA
      auth_passphrase: "..."
      priv_protocol: AES
      priv_passphrase: "..."

gateway:
  trap_sink_community: public

agents:
  - name: plc
    listen_addr: 10.0.0.10:161
    agent_addr: 10.0.0.50:161
    agent_community: public
    security:
      # This agent has its own managers and engine state.
      users:
        - name: plc-monitoring
          auth_protocol: SHA
          auth_passphrase: "..."
          priv_protocol: AES
          priv_passphrase: "..."
      engine_store: /var/lib/snmp-shield/plc-engine.json
    access:
      read_only: true
      allow: ["10.8.0.0/24"]
    trap_listen_addr: 10.0.0.10:162
    trap_sink_addr: 10.8.0.5:162

  - name: ahu
    listen_addr: 10.0.0.11:161
    agent_addr: 10.0.0.51:161
    agent_community: public
    # Inherits security.users; its engine store derives from
    # engine_store_dir as ahu.json.
    access:
      allow: ["10.8.0.0/24"]
      write_policy:
        default: deny
        rules:
          - {oid: "1.3.6.1.4.1.99.1", action: allow}
```

For `tsm-gateway`, an entry can also carry its own `tls` block (CA,
server certificate/key) and `security.tsm_identities`; the top-level
`tunnel` block is the default.

### 6.2 Entry fields

| Field | Required | Meaning |
|---|---|---|
| `name` | no (default `agent_addr`) | unique label; reload match key; metrics/status name |
| `listen_addr` | yes (Phase 1) | front listener for this agent |
| `agent_addr` | yes (Phase 1) | upstream legacy agent |
| `agent_community` | no | v1/v2c community toward the agent (usm/tsm gateway) |
| `access` | no | per-entry policy; falls back to the top-level `access` |
| `trap_listen_addr` | no | clear/v3 notification ingress for this entry |
| `trap_sink_addr` | no | notification sink for this entry |
| `trap_sink_community` | no | clear v2c community toward the sink |
| `security` | no | per-entry override of users, engine ID/store, TSM identities and trap community; the top-level `security` block is the default. `mode` stays process-wide in Phase 1 |
| `tls` | no | per-entry CA/cert/key for `tsm-gateway`; falls back to the top-level `tunnel` block |
| `notifications` | no | per-entry notification filter (Phase 2; global today) |

Phase 1 requires a request path per entry. Trap legs are optional and
per-entry. The existing notification-only shape (a single `gateway` block
with only trap legs) remains unchanged.

### 6.3 Validation

- Either the single-agent `gateway.listen_addr` + `gateway.agent_addr`
  pair or `agents:`, never both.
- `name` unique; default is `agent_addr`. It must not contain path
  separators (it is used in derived engine-store file names).
- `listen_addr` unique across entries and across the process (including
  the metrics listener and trap listeners).
- Each entry: `listen_addr` and `agent_addr` both present (Phase 1
  requires the request path).
- Trap legs both-or-neither per entry. With `agents:`, the single-agent
  `gateway.trap_listen_addr` / `gateway.trap_sink_addr` pair is not
  allowed; `gateway.trap_sink_community` remains a process-wide default.
- Effective security per entry = top-level defaults + entry override.
- Mode-specific checks run per entry:
  - `usm-gateway`: users + an engine store (explicit, or derived from
    `engine_store_dir` + `<name>.json`);
  - `tsm-gateway`: cert/key/CA (entry `tls`, or top-level `tunnel`);
  - `usm-manager-gateway`: agent users (per entry).
- Per-entry engine stores must be unique; duplicate effective paths are
  rejected. Use `engine_store_dir` to derive `<dir>/<name>.json`.
- Per-entry `access` compiles with the same rules as today; an empty
  default-deny policy is rejected.
- `security.mode` is process-wide in Phase 1; an entry override cannot
  change it.

### 6.4 Backward compatibility

- A config with no `agents:` behaves exactly as today.
- A config with `agents:` and the old single-agent fields is a validation
  error, not a silent override.
- Flags mode stays single-agent.

## 7. Security model per mode

Every entry has an **effective security block**: the top-level `security`
provides defaults, the entry's `security` overrides them. This matches
the sibling per-device model: the `devices:`/`agents:` entry is the
security boundary, not the process.

### `usm-gateway`

- Each entry has its own user database, engineID and engine store.
- Per-entry engine stores must be unique. Use `engine_store_dir` to
  derive `<dir>/<name>.json`, or set an explicit `engine_store` per
  entry. Sharing one store across entries is rejected in Phase 1.
- Each entry has its own front listener and access policy.
- A manager authorized for entry A cannot reach entry B unless entry B's
  access policy allows it. The front listener is the boundary.

### `tsm-gateway`

- Each entry can have its own `tls` block (CA, server cert/key) and
  `tsm_identities` allow-list. Top-level `tunnel` values are defaults.
- Each entry has its own raw-DTLS front listener, access policy and agent
  community.
- Client certificates are authenticated per DTLS session; the entry is
  selected by the listener the client connected to.
- `tunnel.max_sessions` is one process-wide budget shared by all entries
  in the multi-agent runner (`tsm.SessionLimiter`), not N × cap. The
  single-agent path uses the same value for its one listener.

### `usm-manager-gateway`

- Each entry needs its own agent v3 credentials (`security.users`) and
  optionally its own engine store for the trap leg.
- The proxy follows each agent's engine; no shared engine state is
  required.
- Per-entry access policy is the front-door boundary.

### Common rules

- No shared front listener.
- No community/context/OID routing.
- No cross-entry traffic.
- Secrets never appear in status or metrics.
- Per-entry access and security are independent; SIGHUP reloads one entry
  by name.

## 8. Trap legs

Phase 1: **per-entry trap legs.**

- Each entry may configure its own `trap_listen_addr` and `trap_sink_addr`.
- This is the simplest change: each `GatewayTranslator` / `ManagerGateway`
  / `TSMGateway` already binds its own trap socket in `Run`.
- It gives clean isolation: one entry's trap traffic cannot affect
  another's.
- Cost: N ports; the operator allocates them.

Later optimization: one shared trap listener. With per-entry security it
needs a source→entry mapping (agent IP or engineID) to pick the right
user/engine/credentials. Do not block Phase 1 on it.

Per-entry `notifications.filter` is supported (see §6.2); the
notification-only shape remains a single-entry process-global feature
for now: one trap listener already aggregates many devices.

## 9. Metrics and status

### Prometheus

- Per-entry counters get an `agent` label (the entry `name`).
- Single-target roles (single-agent gateway and the two-proxy
  manager/agent) use `agent="default"`.
- Process-level gauges (sessions, tunnel state) stay process-level; the
  TSM front-session gauge can gain the same label.
- This is an accepted compatibility change for dashboards. Document it in
  the release notes; the alternative (two metric families) is worse.

### JSON status

Served as `/status` on the metrics HTTP listener (`--metrics-addr`), next
to `/metrics`. A stable JSON document listing every entry:

```json
{
  "ok": true,
  "ready": true,
  "role": "gateway",
  "security_mode": "usm-gateway",
  "tunnel_mode": "dtls",
  "version": "1.2.3",
  "config_hash": "…",
  "config_revision": 4,
  "reload": {
    "attempts": 3,
    "applied": 3,
    "last_ok": true,
    "restart_required": ["agent plc listener/agent changed; restart required"]
  },
  "agents": [
    {
      "name": "plc",
      "listen": "10.0.0.10:161",
      "upstream": "10.0.0.50:161",
      "ready": true,
      "read_only": true,
      "allow_count": 1,
      "rate_per_sec": 50,
      "reload": {
        "policy_applied": true,
        "restart_required": ["listener/agent changed"]
      },
      "counters": {
        "requests_forwarded": 1234,
        "request_errors": 0,
        "notifications_relayed": 12,
        "notifications_filtered": 1,
        "drops": 3,
        "acl_denied": 2,
        "writes_denied": 4,
        "rate_limited": 5,
        "latency_count": 1234,
        "latency_sum_seconds": 0.42
      }
    }
  ]
}
```

`ready` is true only after every configured listener has bound; `ok` is
the same for the whole process (it means the daemon is serving, not that
a device is reachable — use `selftest` for that). `config_hash` is the
SHA-256 of the last successfully loaded YAML file, and `config_revision`
counts those successful loads (starting at 1). `reload` reports the last
SIGHUP: a failed file leaves the hash/revision and the running policy
alone and records `last_error`. Per-entry `reload.restart_required` names
the settings that are still at their bound values while the file says
something else. No communities, USM secrets, PSKs, or key material.

### SNMP MIB

- The process-level scalars stay as they are.
- Per-agent table `<Base>.40.<n>.<col>`: `.1` agent name, `.2`–`.9` the
  eight per-agent counters in `PerAgentCounterList` order (requests
  forwarded/errors, notifications relayed/filtered, drops, ACL denied,
  writes denied, rate limited), `.10` latency count, `.11` latency sum.
- Rows are sorted by agent name. Single-target roles expose one row
  named `default`.
- The table is read-only GET/GETNEXT like the rest of the MIB.

## 10. Lifecycle

- The runner builds one translator per entry. A bind failure in any entry
  aborts startup; the process does not keep serving a partial list.
- Shared objects:
  - `usm-gateway`: one `cache.EngineClock` and one `[]usm.Profile`
    user list; each translator builds its own key cache from them;
  - `tsm-gateway`: one `tunnel.ListenerConfig`;
  - `usm-manager-gateway`: per-entry `Security`.
- Shutdown cancels all entries and waits; one slow entry must not prevent
  the others from stopping.
- SIGHUP:
  - reload each entry's `access` by `name`;
  - report listener/agent/security/TLS/notifications/trap changes as
    `(restart required)`;
  - adding/removing an entry is restart-only in Phase 1;
  - an invalid file keeps the running configuration.
- `validate` iterates entries: config, local resources, address
  uniqueness, mode-specific requirements.
- `selftest` iterates entries: one GET to each agent, optional trap sink
  reachability (warning only).
- Flags mode stays single-agent.

## 11. Implementation plan

### Phase 1 — implemented (2026-11-03)

- `agents:` list for the gateway role, mutually exclusive with the
  single-agent `gateway.listen_addr` / `gateway.agent_addr` pair.
- Per-entry `access`, `security` (users, engine ID/store, TSM identities,
  trap community), `tls` and `notifications` filter; `engine_store_dir`
  derives `<dir>/<name>.json`; duplicate stores are rejected.
- Runner builds one translator per entry with per-entry security/engine/
  TLS/filter; a bind or construction failure aborts startup.
- Per-entry trap legs.
- SIGHUP applies access policy per entry by name; listener/agent/security/
  TLS/notifications/trap changes are reported as restart-required;
  adding/removing an entry is restart-only.
- `validate`/`selftest` iterate entries; JSON checks carry an `agent`
  field.
- Per-agent Prometheus label; single-target roles use `agent="default"`.
- Per-agent SNMP MIB table (`.40.<n>`) with name, the eight per-agent
  counters and latency count/sum.
- `tsm-gateway`: one process-wide `tunnel.max_sessions` budget shared by
  all entries (`tsm.SessionLimiter`), not N × cap.
- `/status` JSON document on the metrics HTTP listener, next to
  `/metrics`, with per-entry endpoints, policy summary and counters,
  per-entry `ready`, the active config revision/hash, and the last
  reload result including restart-required fields. `READY=1` is sent
  only after every entry's listeners have bound.
- Tests: two-entry USM e2e (independent policies, no cross-entry traffic,
  per-agent metrics), per-entry trap delivery and filtering, SIGHUP access
  reload, TSM/manager-gateway bind smoke tests, config validation,
  per-entry selftest, MIB table GET/GETNEXT, shared session limiter,
  a two-entry conformance scenario across all available peers, and a
  two-entry TSM vendor-client scenario over DTLS.

### Phase 2 — follow-ups

- Shared trap listener (optional; needs source→entry mapping with
  per-entry security).

## 12. Test plan

Phase 1 implemented the unit and E2E items below; conformance, mutation
and dedicated soak additions remain Phase 2.

- **Unit**
  - config: mutual exclusion, unique names/listeners/stores, per-entry
    trap pairs, mode-specific requirements, access compilation,
    per-entry notification filters;
  - reload diff by name;
  - MIB table row order, name/counter resolution and GETNEXT.
- **E2E**
  - two entries with different access policies;
  - cross-entry isolation: a client admitted on listener A cannot reach
    agent B;
  - one dead agent does not affect the other;
  - per-entry trap direction and filter;
  - SIGHUP changes one entry only;
  - `selftest` reports each entry;
  - metrics carry the right `agent` label.
- **Conformance**
  - implemented: `TestUSMGatewayAgents` drives a two-entry `agents:`
    config with every available peer (gosnmp, net-snmp 5.6/5.9, pysnmp,
    node); each front listener returns its own device.
  - implemented: `TestTSMGatewayAgentsVendorClient` drives a two-entry
    `tsm-gateway` config with net-snmp over DTLS in the peer container.
- **Mutation checks**
  - removing the per-entry access holder makes the cross-policy test
    fail;
  - sharing one front listener fails validation;
  - removing an entry from the runner makes that agent unreachable.
- **Race/soak**
  - implemented: `TestGatewayAgentsNoPerRequestGoroutines` (100 requests
    to each of two entries; flat goroutines, back to baseline).
  - implemented (soak-gated): `TestSoakMultiAgentSteadyState` (two entries
    under continuous v3 request load plus periodic per-entry traps to both
    sinks; zero unanswered, flat goroutines, bounded live heap). A 20s quick
    pass is green; the full 10-minute run is a release-checklist item.

## 13. Open questions

1. Shared trap listener (Phase 2; needs source→entry mapping with
   per-entry security).

## 14. Decision log

- **S1a reopened:** gateway-only co-hosting, matching the sibling
  `devices:` shape.
- **S1b stays closed:** no multi-agent over the custom tunnel; one pair
  per agent.
- **No routing:** no shared front listener, no community/context/OID
  selection, no cross-entry traffic.
- **Security is per entry:** users, engine state, TSM identities/TLS and
  access policy follow the `agents:` entry, matching the sibling
  per-device model; top-level blocks are defaults.
- **One mode per process:** real-world deployments standardize on one
  gateway mode; mixed modes are separate instances.
- **Per-agent Prometheus label:** accepted compatibility change;
  single-agent configs use `agent="default"`.
- **JSON status:** served as `/status` on the metrics listener; per-entry
  endpoints, policy summary and counters, per-entry `ready`, active config
  revision/hash and the last reload result; no secrets.
- **TSM front-session cap:** one process-wide `tunnel.max_sessions`
  budget shared by all entries, not one cap per entry.
- **Phase 1 implemented (2026-11-03):** all gateway modes (one mode per
  process), per-entry security/access/trap legs/filters, per-agent metrics
  label and MIB table, per-entry validate/selftest/reload.
