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
snmp-proxy gateway \
  --security usm-manager \
  --trap-listen :162 \
  --trap-sink <manager-ip>:162 \
  --auth-pass myauth --priv-pass mypriv
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
snmp-proxy selftest --role gateway --security usm-manager \
  --trap-listen :162 --trap-sink <manager-ip>:162 \
  --auth-pass myauth --priv-pass mypriv --agent 127.0.0.1:161 --probe=false
```

(USM-manager has no request path — it secures notifications only. The
selftest validates config + engine store.)

## Config file

`configs/gateway-usm-manager.yaml` — engine store placement and user
list.
