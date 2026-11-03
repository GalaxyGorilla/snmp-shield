# Operations (day-2: install, commission, monitor, troubleshoot)

This is the common starting point for running SNMP Shield. It is deliberately
a map as well as a checklist: deeper material lives in the linked documents,
so you do not have to read one giant file.

| I need to… | Go to |
|---|---|
| Understand the security model and its limits | [`../SECURITY.md`](../SECURITY.md) |
| Pick a deployment shape | [`../README.md#deployment-shapes`](../README.md#deployment-shapes) and [`README.md`](README.md) |
| Install the binary and a systemd unit | [Install](#install) |
| Validate and commission a config | [Commission](#commission) |
| Watch the box | [Monitor](#monitor) |
| Change policy without downtime | [Reload](#reload) |
| Diagnose "no answer", auth or tunnel failures | [Troubleshoot](#troubleshoot) |
| Upgrade or roll back | [Upgrade](#upgrade) |
| Run several agents in one process | [`../docs/multi-agent.md`](../docs/multi-agent.md) |
| Run two proxies with failover | [`ha-two-proxy.md`](ha-two-proxy.md) |
| See what the tests actually prove | [`../TESTING.md`](../TESTING.md) and [`../CONFORMANCE.md`](../CONFORMANCE.md) |

## Host assumptions

- Linux with systemd is the supported appliance shape; the binary is static
  and has no runtime dependencies.
- A dedicated `snmp-shield` user/group owns the config and engine store.
- The clear SNMP leg next to the legacy device/manager is on a protected
  segment. The proxy does not authenticate that leg; see
  [`../SECURITY.md`](../SECURITY.md).
- UDP ports: the front leg and trap listener are configurable; the device leg
  uses ephemeral source ports. Open only what the chosen shape needs.

## Install

```sh
# build (or take a release binary)
go build -o bin/snmp-shield ./cmd/snmp-shield

# on the box
sudo install -m 0755 bin/snmp-shield /usr/local/bin/snmp-shield
sudo useradd --system --home /var/lib/snmp-shield --shell /usr/sbin/nologin snmp-shield
sudo install -d -o snmp-shield -g snmp-shield /etc/snmp-shield /var/lib/snmp-shield

# pick the unit for the role: gateway, manager or agent
sudo cp deploy/snmp-shield-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now snmp-shield-gateway
```

The shipped units are `Type=notify` with `WatchdogSec=30`, a hardened sandbox,
`ExecReload=kill -HUP`, and `CAP_NET_BIND_SERVICE` for privileged ports. Copy
the matching config template from `configs/` and edit it.

## Commission

```sh
# 1. syntax, addresses, policy compile, TLS files, engine store
sudo -u snmp-shield snmp-shield validate --role gateway \
  --config /etc/snmp-shield/gateway.yaml

# 2. probe the environment: engine store, tunnel handshake, a real GET
sudo -u snmp-shield snmp-shield selftest --role gateway \
  --config /etc/snmp-shield/gateway.yaml

# 3. start it and confirm readiness
sudo systemctl restart snmp-shield-gateway
systemctl status snmp-shield-gateway
curl -fsS "http://${METRICS_ADDR:-127.0.0.1:9100}/status" | jq .

# 4. prove the data path with a real manager/agent, not only the selftest
snmpget -v3 -l authPriv -u proxy -a SHA -A '…' -x AES -X '…' \
  127.0.0.1:161 1.3.6.1.2.1.1.1.0
```

`validate` and `selftest` accept `--json` for a web UI or pre-apply hook.
`selftest` reports "not probed" when its deadline is spent, so a slow device
does not look like a broken config.

## Monitor

- **Prometheus**: `metrics.listen_addr` serves `/metrics` and `/status`.
  `/status` is the daemon contract: `ready`, per-entry readiness, active config
  revision/hash, last reload result and restart-required fields. It never
  contains communities, USM secrets, PSKs or key material.
- **SNMP health MIB**: `metrics.listen_addr` also answers a read-only v2c
  health MIB; the per-agent table is `.40.<n>`. `metrics.trap_sink_addr` sends
  tunnel lifecycle traps.
- **Systemd**: `Type=notify` means `systemctl is-active` is not enough; check
  that the unit reached `READY=1` and that watchdog pings continue. A bind
  failure exits without advertising readiness.
- **Logs**: structured JSON. Look for `reload: … restart required`,
  `session cap reached`, `discovery failed`, `timeliness`, and
  `upstream error`. Secrets are never logged.

Useful counters: requests forwarded/errors, notifications relayed/filtered,
drops, ACL denied, writes denied, rate limited, sessions active/denied, tunnel
reconnects, and forward latency.

## Reload

```sh
sudo systemctl reload snmp-shield-gateway   # SIGHUP
```

`SIGHUP` re-reads the YAML and swaps the **access policy** (and per-entry
access policies) in place. Everything socket- or crypto-bound — role, tunnel,
listeners, `security.users`, engine identity, TLS material, notification
filters, trap legs, metrics endpoints — needs a restart and is logged as
`(restart required)`. An invalid file keeps the running configuration.

After a reload, check `/status`: `reload.last_ok` should be true, the config
revision/hash should have moved, and any `restart_required` field names what
still needs a restart. A failed reload leaves the hash/revision and the running
policy alone and records `last_error`.

## Troubleshoot

| Symptom | First checks |
|---|---|
| `systemctl start` fails | `journalctl -u snmp-shield-gateway`; a bind error exits non-zero and never sends `READY=1` |
| `/status` says `ready:false` | At least one configured listener did not bind; check the log for the address and the process exit |
| Manager gets `timeout` | Is the front leg bound? Does `selftest` reach the agent? Check ACL/rate counters and the clear-leg path |
| v3 request is rejected | User/protocol/passphrase mismatch, security level weaker than configured, or timeliness (`engineBoots`/time) |
| `timeliness` after a restart | The engine store is missing or memory-only; `security.ephemeral_engine` resets boots and weakens replay protection |
| Tunnel stays down | PSK/certificate/CA mismatch, `dial_addrs` unreachable, or a firewall dropping DTLS/TLS; check `tunnel_reconnects` and `tunnel_up` |
| Traps/informs do not arrive | Trap listener/sink addresses, notification filter, and whether the sink answers receiver-side discovery for informs |
| Reload did not change a listener | That field is restart-required by design; check `/status.reload.restart_required` |
| Goroutines or memory grow | Run `make soak`; the fast regression nets are `TestNoPerRequestGoroutines` and `TestGatewayAgentsNoPerRequestGoroutines` |

For a suspected security issue, follow [`../SECURITY.md`](../SECURITY.md)
instead of attaching secrets or captures to a public issue.

## Upgrade

```sh
# build/verify the new binary first
make verify
sudo systemctl stop snmp-shield-gateway
sudo install -m 0755 bin/snmp-shield /usr/local/bin/snmp-shield
sudo systemctl start snmp-shield-gateway
curl -fsS "http://${METRICS_ADDR:-127.0.0.1:9100}/status" | jq .
```

The engine store is persistent and must survive the upgrade; deleting it resets
`engineBoots` and weakens replay protection. Keep the previous binary and
config until the new one reports ready and answers a real request. Roll back by
restoring both and restarting.

## Security notes

- The clear device/manager leg is not encrypted; isolate it.
- Use USM authPriv, TSM/DTLS, or the two-proxy tunnel for any untrusted path.
- Keep the engine store on persistent storage and back it up with the config.
- Restrict the config file and key material to the service user.
- Run `make conformance-required` and `make security` before a release.
- Real-device timing, vendor quirks and regulatory validation remain
  commissioning work; see [`../TESTING.md`](../TESTING.md).
