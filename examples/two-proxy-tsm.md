# Two-proxy TSM (certificate-based)

Same topology as [two-proxy-usm](two-proxy-usm.md), but the secured
segment uses RFC 5591 TSM: the (D)TLS handshake **is** the SNMP
authentication. No PSK, no USM user — the peer certificate (leaf CN) is
the securityName, and the agent side allow-lists identities.

```
[manager] --clear v2c/v3--> [manager-side proxy]
       === TSM over cert-DTLS ===
       [agent-side proxy] --clear v2c/v3--> [real agent]
```

## 1. PKI

Each proxy needs a certificate; the agent side needs the CA that signs
the manager-side cert. For testing:

```bash
scripts/gen-certs.sh   # throwaway PKI into certs/ (gitignored)
```

In production use your appliance PKI.

## 2. Agent-side box

```bash
snmp-proxy agent \
  --tunnel-addr <agent-box-ip>:19611 \
  --tunnel-mode dtls \
  --security passthrough \
  --ca-file /etc/snmp-proxy/ca.crt \
  --cert-file /etc/snmp-proxy/agent.crt \
  --key-file /etc/snmp-proxy/agent.key \
  --agent 127.0.0.1:161 \
  --community public
```

Restrict which client certificates may connect by listing identities in
the config file (`security.tsm_identities`; empty = accept any valid
cert from the trusted CA). Flags mode defaults to passthrough; switch to
TSM end-to-end via the YAML config (`configs/agent-tsm.yaml`).

## 3. Manager-side box

```bash
snmp-proxy manager \
  --tunnel-addr <agent-box-ip>:19611 \
  --tunnel-mode dtls \
  --security passthrough \
  --ca-file /etc/snmp-proxy/ca.crt \
  --cert-file /etc/snmp-proxy/manager.crt \
  --key-file /etc/snmp-proxy/manager.key \
  --listen :161
```

## 4. Verify

```bash
snmp-proxy selftest --role manager --tunnel-addr <agent-box-ip>:19611 \
  --tunnel-mode dtls --security passthrough \
  --ca-file /etc/snmp-proxy/ca.crt --cert-file /etc/snmp-proxy/manager.crt \
  --key-file /etc/snmp-proxy/manager.key --listen :161
```

A failed handshake (untrusted cert, wrong CA) shows up immediately:

```
  tunnel <agent-box-ip>:19611 FAIL   dtls dial: ...
```

## Config files

`configs/manager-tsm.yaml` + `configs/agent-tsm.yaml` — full TSM mode
(`security.mode: tsm`): the tunnel handshake maps to the SNMP
securityName, the agent side checks `security.tsm_identities`.

## Hardening option

- **Notification filtering** — drop unwanted notifications at the
  clear-ingress point (the box's `--trap-listen`) before they enter the
  secured segment:

  ```bash
  snmp-proxy manager --trap-listen :10162 \
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

- **PSK ciphersuite** — not applicable in TSM mode (the handshake is
  certificate-based, no PSK suites involved).
