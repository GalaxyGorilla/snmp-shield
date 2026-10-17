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
