# USM manager (one box, protects the manager leg)

The mirror of [gateway-usm](gateway-usm.md): a single proxy in front of
the **manager**. Legacy devices keep firing clear traps/informs at
"the manager" (the proxy); the proxy wraps each into an authenticated
SNMPv3 USM notification toward the manager's real trap receiver.

```
[legacy devices] --clear v2c/v1 traps/informs--> [proxy] --SNMPv3 USM authPriv--> [manager's trap receiver]
```

Use when the devices are too old for v3 but the manager side must only
accept authenticated notifications (audited networks, segmented
management VLANs).

## 1. Run it

```bash
snmp-shield gateway \
  --security usm-manager \
  --trap-listen :162 \
  --trap-sink <manager-ip>:162 \
  --auth-pass myauthpass --priv-pass myprivpass
```

- `--trap-listen` — what the devices fire at (the proxy's clear leg).
- `--trap-sink` — the manager's v3 USM trap receiver. The proxy wraps
  every clear trap/inform into an authenticated v3 notification (its own
  authoritative engine, user `proxy`, SHA auth + AES privacy) and sends
  it here.
- `--auth-pass`/`--priv-pass` — the USM credentials the manager's
  receiver is configured to accept.

## 2. Point the devices at the proxy

Devices fire at the proxy's `--trap-listen` instead of the manager.
Informs work end-to-end: the manager's confirmation flows back through
the proxy to the device.

## 3. Verify

```bash
# device-reachability check from the proxy box:
snmp-shield selftest --role gateway --security usm-manager \
  --trap-listen :162 --trap-sink <manager-ip>:162 \
  --auth-pass myauthpass --priv-pass myprivpass --probe=false
```

(USM-manager has no request path — it secures notifications only. The
selftest validates config + engine store.)

## Hardening option

- **Notification filtering** — the natural place for it: drop the
  uninteresting device traps at the clear ingress, so only the ones
  that matter are wrapped into authenticated v3 toward the manager:

  ```bash
  snmp-shield gateway --trap-listen :162 \
    --filter-oid 1.3.6.1.4.1.99 --filter-action deny ...
  ```

  `--filter-oid` is an OID prefix (repeatable, arc-boundary match),
  `--filter-action` is `allow` or `deny`. In YAML:
  `notifications.filter` (see `configs/gateway-usm-manager.yaml`).

- **SNMP metrics interface** — expose the proxy's own health over SNMP
  (optional, all roles): `--metrics-snmp-listen <ip:port>` serves a
  read-only SNMPv2c health MIB (GET/GETNEXT: identity, tunnel state,
  counters) and `--metrics-snmp-trap-sink <ip:port>` emits v2c traps on
  tunnel lifecycle changes (up/down, HA failover). `--metrics-snmp-base-oid`
  (default `.1.3.6.1.4.1.58427.1`) and `--metrics-snmp-community`
  (default "public") apply to both. Prometheus (`--metrics-addr`) stays
  available alongside. In YAML: `metrics:`.
## Config file

`configs/gateway-usm-manager.yaml` — engine store placement and user
list.
