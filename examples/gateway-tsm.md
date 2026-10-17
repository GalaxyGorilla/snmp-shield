# TSM gateway (one box, DTLS front leg)

A single proxy in front of a legacy v2c-only agent, fronted by
SNMP-over-DTLS per RFC 6353: the (D)TLS handshake with a client
certificate **is** the authentication. One SNMP datagram per DTLS
record, no frame layer — 100% standard SNMP on the wire.

```
[standard TSM client] --SNMP-over-DTLS (RFC 6353)--> [gateway] --clear v2c--> [legacy agent]
```

Caveat: few mainstream managers speak TSM (net-snmp does; Zabbix/PRTG do
not). Prefer [gateway-usm](gateway-usm.md) unless your clients are
net-snmp-based.

## 1. PKI

The gateway presents a server certificate and verifies client
certificates against the CA. For testing:

```bash
scripts/gen-certs.sh   # throwaway PKI into certs/
```

## 2. Run it

```bash
snmp-shield gateway \
  --security tsm-gateway \
  --listen :10161 \
  --agent 127.0.0.1:161 \
  --ca-file /etc/snmp-shield/ca.crt \
  --cert-file /etc/snmp-shield/gateway.crt \
  --key-file /etc/snmp-shield/gateway.key \
  --community public \
  --trap-listen :10162 \
  --trap-sink <manager-ip>:10162
```

- `--listen` — the raw DTLS front leg.
- `--ca-file` — client certificates must chain to this CA.
- `--trap-listen`/`--trap-sink` — clear device traps in, TSM
  notifications out toward the manager's DTLS trap receiver.

Restrict client identities via the config file
(`security.tsm_identities`; the peer certificate CN must be on the list;
empty = accept any valid cert from the trusted CA).

## 3. Point the client at the gateway

net-snmp with a client certificate (see `scripts/interop-gateway-tsm.sh`
for the full snmp.conf incantation):

```bash
snmpget -v3 -l authPriv -m ALL -M <mibdirs> \
  dtls:<gateway-host>:10161 sysDescr.0
```

## 4. Verify

```bash
snmp-shield selftest --role gateway --security tsm-gateway \
  --listen :10161 --agent 127.0.0.1:161 \
  --ca-file /etc/snmp-shield/ca.crt --cert-file /etc/snmp-shield/gateway.crt \
  --key-file /etc/snmp-shield/gateway.key
```

The selftest also warns when the front certificate expires within 30
days.

## Hardening option

- **Notification filtering** — drop the uninteresting device traps at
  the clear ingress (`--trap-listen`) before they are wrapped into
  TSM notifications toward the manager:

  ```bash
  snmp-shield gateway --trap-listen :10162 \
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

- **PSK ciphersuite** — not applicable here (the front leg is
  certificate-based DTLS, no PSK suites involved).
