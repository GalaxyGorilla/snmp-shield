# HA two-proxy (redundant agent side)

Extends [two-proxy-usm](two-proxy-usm.md) with failover: the manager
side dials a **list** of agent-side proxies (most preferred first) and
redundant replicas share one engine identity so USM clients never reset
their engine clocks after a failover.

```
                 ┌── [agent-side proxy A] --clear--> [agent]
[manager-side] ──┤                === replica ===
                 └── [agent-side proxy B] --clear--> [agent]
```

## 1. Configure the failover list

Manager side — `--tunnel-addr` accepts a comma-separated list:

```bash
snmp-proxy manager \
  --tunnel-addr <agent-a-ip>:19611,<agent-b-ip>:19611 \
  --psk <KEY> --auth-pass myauth --priv-pass mypriv \
  --listen :161
```

Or in YAML (`tunnel.dial_addrs`, most preferred first):

```yaml
tunnel:
  dial_addrs:
    - "10.0.0.11:19611"
    - "10.0.0.12:19611"
  psk: "hex:..."
  keepalive_secs: 10
```

Behavior:

- Sticky failover — the last-known-good endpoint is preferred; dead
  peers are detected via keepalive (3 missed probes at 3× the keepalive
  interval) and the next endpoint takes over automatically.
- `keepalive_secs` and `max_reconnect_backoff_secs` tune detection and
  reconnect pacing.

## 2. Share the engine identity

Both agent-side replicas must use the SAME `security.engine_id` so
managers see one engine across the failover:

```yaml
# /etc/snmp-proxy/agent.yaml (both replicas)
security:
  mode: usm-translate
  engine_id: "hex:8000f2a4..."
  engine_store: /var/lib/snmp-proxy/engine.json   # local per replica
```

Generate the engine ID once:

```bash
snmp-proxy genpsk   # or any hex string; engine IDs are opaque bytes
```

Engine-state convergence is automatic: after a failover, a verified
higher engineBoots claim is adopted as a logical reboot (the replicas
converge on the highest seen engine state), and the manager's discovery
cache follows the wire. Managers do not need to re-discover.

## 3. Verify

```bash
# from the manager box: both endpoints must handshake
snmp-proxy selftest --role manager \
  --tunnel-addr <agent-a-ip>:19611 --psk <KEY> \
  --auth-pass myauth --priv-pass mypriv --listen :161

snmp-proxy selftest --role manager \
  --tunnel-addr <agent-b-ip>:19611 --psk <KEY> \
  --auth-pass myauth --priv-pass mypriv --listen :161
```

Kill proxy A and watch the manager-side log: the tunnel drops, the
dialer walks to B, and polling resumes without manager reconfiguration.

## Hardening options

- **PSK ciphersuite** — pin the DTLS tunnel suite on all boxes (both
  manager sides and both agent-side replicas must share at least one
  entry):

  ```bash
  snmp-proxy manager --psk-ciphersuites aes256-ccm-8 ...
  snmp-proxy agent   --psk-ciphersuites aes256-ccm-8 ...
  ```

  Comma-separated, most preferred first (see `--help`). In YAML:
  `tunnel.psk_ciphersuites`.

- **Notification filtering** — drop unwanted traps/informs at any
  `--trap-listen` before they enter the secured segment:

  ```bash
  snmp-proxy manager --trap-listen :10162 \
    --filter-oid 1.3.6.1.4.1.99 --filter-action deny ...
  ```

  `--filter-oid` is an OID prefix (repeatable, arc-boundary match),
  `--filter-action` is `allow` or `deny`. In YAML:
  `notifications.filter`.
