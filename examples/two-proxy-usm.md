# Two-proxy USM (the flagship deployment)

Two proxy boxes between a legacy manager and a legacy agent. The local
legs stay plain SNMP (whatever the endpoints already speak); the
long-haul segment between the proxies is upgraded to SNMPv3 authPriv
(SHA auth + AES privacy).

```
[manager] --clear v2c/v3--> [manager-side proxy]
       === v3 authPriv over PSK-DTLS ===
       [agent-side proxy] --clear v2c/v3--> [real agent]
```

End devices are untouched: the manager still points at "an agent" (the
proxy's clear leg), the agent still answers a manager (the proxy's clear
leg). Everything in between is authenticated and encrypted.

## 1. Generate one key

On either box:

```bash
snmp-proxy genpsk
# e.g. 4f0b0c1d... (64 hex chars)
```

## 2. Agent-side box (next to the real agent)

```bash
snmp-proxy agent \
  --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> \
  --auth-pass myauth --priv-pass mypriv \
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
snmp-proxy manager \
  --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> \
  --auth-pass myauth --priv-pass mypriv \
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
snmp-proxy validate --role manager --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> --auth-pass myauth --priv-pass mypriv --listen :161

# full environment check from the manager box (tunnel handshake):
snmp-proxy selftest --role manager --tunnel-addr <agent-box-ip>:19611 \
  --psk <KEY> --auth-pass myauth --priv-pass mypriv --listen :161

# from the agent box (SNMP GET to the real agent):
snmp-proxy selftest --role agent --tunnel-addr :19611 --psk <KEY> \
  --auth-pass myauth --priv-pass mypriv --agent 127.0.0.1:161
```

Then poll through the chain with any manager (`snmpget -v2c -c public
<manager-box-ip> sysDescr.0`).

## Config files

The same deployment via YAML (`--config`):

```bash
snmp-proxy manager --config configs/manager-usm.yaml
snmp-proxy agent   --config configs/agent-usm.yaml
```

Both sides must share `--psk`, `--auth-pass` and `--priv-pass` (the
tunnel PSK authenticates the transport; the USM user `proxy`
authenticates the SNMP messages inside it).
