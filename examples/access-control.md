# Access control and live reload

Every deployment shape has a request leg with a peer: managers on the
clear leg, v3 clients on the gateway front leg, DTLS clients on a TSM
front leg. The `access` section governs that leg — **who** may talk to the
proxy, **how fast**, and **what may be written** — and it is the one block
that `SIGHUP` can swap without a restart.

```
[client] --request--> [snmp-shield: allow-list -> rate limit -> write policy] --> [device]
```

This walkthrough applies the same policy to a single-box gateway; the
section is identical for the `manager` role (its clear manager leg). On
the `agent` role the write policy still applies — requests arrive over
the tunnel, so the device-facing box refuses writes even if the manager
side is compromised — but `allow`/`rate_per_sec` have no client address
to work with and are reported as ignored at startup. The notification
legs are governed by `notifications.filter` instead.

## 1. Lock down the front leg

`configs/gateway-usm.yaml` with an access section:

```yaml
gateway:
  listen_addr: ":161"
  agent_addr: "127.0.0.1:161"
  agent_community: "public"
security:
  mode: usm-gateway
  engine_store: /var/lib/snmp-shield/engine.json
  users:
    - name: noc
      auth_protocol: sha
      auth_passphrase: ...
      priv_protocol: aes
      priv_passphrase: ...

access:
  allow: ["10.8.0.0/24", "192.168.1.5"]   # monitoring station + NMS host
  rate_per_sec: 50                        # per client; 0 = unlimited
  write_policy:
    default: deny                         # nothing is writable by default
    rules:
      - {oid: "1.3.6.1.4.1.99.1",   action: allow}  # our writable subtree
      - {oid: "1.3.6.1.4.1.99.1.9", action: deny}   # except the lockout leaf
```

Flags mode equivalent:

```bash
snmp-shield gateway --security usm-gateway --listen :161 --agent 127.0.0.1:161 \
  --auth-pass myauthpass --priv-pass myprivpass \
  --allow 10.8.0.0/24 --allow 192.168.1.5 \
  --rate-per-sec 50 \
  --write-default deny \
  --write-allow 1.3.6.1.4.1.99.1 \
  --write-deny 1.3.6.1.4.1.99.1.9
```

Coarse alternative — refuse every write, allow every read:

```bash
snmp-shield gateway --security usm-gateway --listen :161 --agent 127.0.0.1:161 \
  --auth-pass myauthpass --priv-pass myprivpass --read-only
```

`read_only` and `write_policy` are mutually exclusive (`--read-only` with
`--write-allow`/`--write-deny` is rejected at startup). `allow` and
`rate_per_sec` combine freely with either.

## 2. What the client sees

| Attempt | Result |
|---|---|
| Read (`GET`/`GETNEXT`/`GETBULK`) from an allowed client, under the rate | Served normally |
| Any request from a client **not** on `allow` | **Silence** (no answer, nothing forwarded) |
| Requests beyond `rate_per_sec` from one client | **Silence** (no answer, nothing forwarded) |
| `SET` inside an allowed subtree, covering every object | Forwarded to the device |
| `SET` touching any denied object, or uncovered with `default: deny` | Answered `notWritable` (`v1`: `noSuchName`), never forwarded |

Silence for off-list and over-rate traffic is deliberate: answering would
disclose that a proxy sits there and would amplify a flood. A write
refusal is *answered* instead, because the peer is already authenticated
and legitimate — making it retransmit into a policy wall would only spin.

Rule semantics are **deny-overrides, allow-must-cover**, evaluated as a
set (config order does not matter):

- touching **one** denied object rejects the whole `SET` — a write can
  never straddle an allowed and a forbidden subtree;
- an allow wins only if a single rule covers **every** object in the
  request;
- otherwise `default` decides (`deny` unless you write `allow`).

OID matching is prefix-based on arc boundaries: `1.3.6.1.4.1.99` covers
`…99.5.0` but not `…9999.1`.

## 3. Verify from the wire

```bash
# off-list client (drop): point at it from an address outside the allow-list
snmpget -v3 -l authPriv -u noc -a SHA -A ... -x AES -X ... <gateway> sysDescr.0
#   -> timeout; nothing appears in the gateway's request counter

# allowed write inside the subtree
snmpset -v3 -l authPriv -u noc ... <gateway> 1.3.6.1.4.1.99.1.0 i 42
#   -> No error

# write outside the policy
snmpset -v3 -l authPriv -u noc ... <gateway> 1.3.6.1.2.1.1.5.0 s nope
#   -> Error in packet ... Reason: notWritable (or noSuchName over v1)

# the proxy's own view
curl -s localhost:9672/metrics | grep -E 'acl_denied|writes_denied|rate_limited'
```

The counters are `snmp_shield_acl_denied_total`,
`snmp_shield_writes_denied_total` and `snmp_shield_rate_limited_total`;
they are also rows in the SNMP health MIB (`metrics.listen_addr`) and
Prometheus.

## 4. Change the policy without a restart

Cut off a noisy client or open a write path during an incident:

```bash
$EDITOR /etc/snmp-shield/gateway.yaml    # edit the access: block
systemctl reload snmp-shield-gateway      # or: kill -HUP <pid>
journalctl -u snmp-shield-gateway -n 5
#   "SIGHUP: configuration reloaded"  access="read-only, 0 write rules"
```

- The policy is read **per datagram**, so the swap applies to the next
  packet — no rebind, no dropped session, no re-discovery.
- Only the `access` block is reloadable. Everything socket- or
  crypto-bound (tunnel, `security.users`, listeners, notification
  filters, metrics endpoints) is logged as `(restart required)` rather
  than silently ignored.
- An invalid file, or a policy that does not compile, **keeps the running
  policy** — a reload typo must never leave the box unprotected or wide
  open.
- Flags-mode processes have no file to re-read: `SIGHUP` is a logged
  no-op there.

## Notes and limits

- **Passthrough cannot police v3.** `security.mode: passthrough` forwards
  SNMPv3 messages opaquely, so `read_only`/`write_policy` only see v1/v2c
  requests (and on the agent side, no tunnel traffic at all). The proxy
  warns about this at startup when both are configured. `usm-translate`,
  `usm-gateway`, `usm-manager-gateway`, `tsm` and `tsm-gateway` all
  inspect the inner PDU, so the policy is complete there.
- **The allow-list sees the source IP** of the datagram. Behind a NAT or
  load balancer that is the middlebox's address — allow-list the
  middlebox, and use authentication (USM/TSM) for identity.
- **Rate limiting is per client IP**, with a full second's burst absorbed
  (a `rate_per_sec: 50` limit admits a 50-request burst, then refills).
  The bucket table is swept and capped (4096 clients) so a spoofed-source
  flood cannot grow it without bound; once full, new clients are refused
  rather than admitted.
- **Notifications are out of scope here** — traps and informs are filtered
  by OID with `notifications.filter` and never pass through the write
  policy.
