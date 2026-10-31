# Two-proxy USM (the flagship deployment)

Two proxy boxes between a legacy manager and a legacy agent. The local
legs stay plain SNMP (whatever the endpoints already speak); the
long-haul segment between the proxies is upgraded to SNMPv3 authPriv
(SHA auth + AES privacy).

```mermaid
flowchart LR
    M["Existing manager"]
    P1["Manager-side proxy"]
    P2["Agent-side proxy"]
    A["Existing agent"]
    M <-->|"existing local SNMP"| P1
    P1 <-->|"authenticated + encrypted<br/>PSK-DTLS tunnel"| P2
    P2 <-->|"existing local SNMP"| A
```

End devices are untouched: the manager still points at "an agent" (the
proxy's clear leg), the agent still answers a manager (the proxy's clear
leg). Everything in between is authenticated and encrypted.

## 1. Generate one key

On either box:

```bash
snmp-shield genpsk
# e.g. 4f0b0c1d... (64 hex chars)
```

## 2. Agent-side box (next to the real agent)

```bash
snmp-shield agent \
  --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> \
  --auth-pass myauthpass --priv-pass myprivpass \
  --agent 127.0.0.1:161 \
  --community public \
  --trap-listen :162 \
  --trap-sink <manager-ip>:10162
```

- `--tunnel-addr` — what the manager-side box dials (this box listens).
- `--agent` — the real agent. Point it at `127.0.0.1:161` when the proxy
  runs on the agent host itself.
- `--community` — the v2c community used toward the real agent.
- `--trap-listen` — optional: devices here fire clear traps at this box
  (they would normally fire at the manager), and the box ships them
  across the tunnel.
- `--trap-sink` — where tunnel-arriving notifications are delivered as
  clear v2c (the real manager's trap receiver).

## 3. Manager-side box (next to the manager)

```bash
snmp-shield manager \
  --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> \
  --auth-pass myauthpass --priv-pass myprivpass \
  --listen :161 \
  --community public \
  --trap-listen :10162
```

- `--tunnel-addr` — the agent-side box (dials, reconnects with backoff).
- `--listen` — what managers poll instead of the agent.
- `--trap-listen` — devices/relays that fire clear traps here (they
  would normally fire at the manager); the box wraps them into
  authenticated v3 across the tunnel.

## 4. Repoint the endpoints

- Manager: poll `<manager-box-ip>:161` instead of the agent.
- Devices: fire traps at `<manager-box-ip>:10162` (or the agent box's
  `:162`) instead of the manager.
- The real manager's trap receiver stays as the agent box's
  `--trap-sink`.

## 5. Verify

```bash
# config sanity (also pre-flights nothing external):
snmp-shield validate --role manager --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> --auth-pass myauthpass --priv-pass myprivpass --listen :161

# full environment check from the manager box (tunnel handshake):
snmp-shield selftest --role manager --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> --auth-pass myauthpass --priv-pass myprivpass --listen :161

# from the agent box (SNMP GET to the real agent):
snmp-shield selftest --role agent --tunnel-addr :19611 --psk <KEY> \
  --auth-pass myauthpass --priv-pass myprivpass --agent 127.0.0.1:161
```

Then poll through the chain with any manager (`snmpget -v2c -c public
<manager-box-ip> sysDescr.0`).

## Config files

The same deployment via YAML (`--config`):

```bash
snmp-shield manager --config configs/manager-usm.yaml
snmp-shield agent   --config configs/agent-usm.yaml
```

Both sides must share `--psk`, `--auth-pass` and `--priv-pass` (the
tunnel PSK authenticates the transport; the USM user `proxy`
authenticates the SNMP messages inside it).

## Hardening options

- **PSK ciphersuite** — the DTLS tunnel defaults to
  `TLS_PSK_WITH_AES_128_CCM_8`. To pin a stronger suite (and reject
  peers offering only weaker ones):

  ```bash
  # both sides:
  snmp-shield agent --psk-ciphersuites aes256-ccm-8 ...
  snmp-shield manager --psk-ciphersuites aes256-ccm-8 ...
  ```

  Comma-separated list, most preferred first (see `--help` for the
  available suites). Both sides must share at least one entry.

- **Notification filtering** — drop unwanted traps/informs at the
  clear-ingress point (the box's `--trap-listen`) before they enter the
  secured segment:

  ```bash
  snmp-shield manager --trap-listen :10162 \
    --filter-oid 1.3.6.1.4.1.99 --filter-action deny ...
  ```

  `--filter-oid` is an OID prefix (repeatable, arc-boundary match),
  `--filter-action` is `allow` or `deny`. In YAML:
  `notifications.filter`.

- **SNMP metrics interface** — expose the proxy's own health over SNMP
  (optional, all roles): `--metrics-snmp-listen <ip:port>` serves a
  read-only SNMPv2c health MIB (GET/GETNEXT: identity, tunnel state,
  counters) and `--metrics-snmp-trap-sink <ip:port>` emits v2c traps on
  tunnel lifecycle changes (up/down, HA failover). `--metrics-snmp-base-oid`
  (default `.1.3.6.1.4.1.58427.1`) and `--metrics-snmp-community`
  (default "public") apply to both. Prometheus (`--metrics-addr`) stays
  available alongside. In YAML: `metrics:`.
