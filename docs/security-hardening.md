# Security hardening review

Two commits, both on top of `346b1be`:

| Commit | Scope |
|---|---|
| `679c555` | Fixes four wire-reachable defects, adds engine-store/credential validation |
| `3f68a3d` | Adds the request-leg access policy (clients, rate, writes) + SIGHUP reload |

This document is a review artifact: what was wrong, what changed, what proves
the fix, and what was deliberately left alone. It is not a deployment
walkthrough — for that see the README and `examples/access-control.md`.

---

## Part 1 — Defects (`679c555`)

All four were reproduced on the wire before being fixed. The two USM bugs were
proved with throwaway PoC tests that drove a real gateway over loopback; the
config bugs were proved by starting the binary with a config it should have
refused.

### D1. Security-level downgrade (the serious one)

**Symptom.** A user configured as `authPriv` could be served a message that
arrived with the *auth* and/or *priv* flag bits cleared. The proxy verified
whatever was present — nothing — and answered. The peer got a full
authenticated-looking response while claiming no authentication at all.

**Why it matters.** This is the exact property the product sells. A
configuration that says `authPriv` must mean "I will not speak to you unless
you authenticate and encrypt"; otherwise the mode is theatre and an attacker on
the wire can downgrade any conversation to cleartext.

**Fix.** `enforceSecurityLevel` (`internal/usm/translate_helpers.go`) compares
the message's requested level against the user's compiled profile on *every*
inbound path, before any request is served:

- the gateway front leg (`gateway.go`),
- the agent-side tunnel ingress (`translate_agent.go`),
- inbound notifications (`receiveNotif`).

Both directions are rejected: asking for *more* than the user can provide, and
asking for *less* (the downgrade / bypass). A refusal is reported through the
existing `dropOrReport` path, so a reportable message gets a proper
`usmStatsUnsupportedSecLevels` Report and a non-reportable one is dropped in
silence, per RFC 3414 §4.

**Proof.** `internal/usm/security_level_test.go` — 300 lines of table-driven
coverage plus wire tests: an `authPriv` user hammered with NoAuthNoPriv and
authNoPriv drifts is refused, an `authNoPriv` user is served at its own level,
and a `none`/`none` user is still served at NoAuthNoPriv where the mode allows
it.

### D2. Plaintext scopedPDU was split twice

**Symptom.** For a message without the priv flag, the code path split the
scopedPDU twice: `ParseV3` already separates context and PDU, and the handler
then called the unwrap routine again on the result. Depending on the PDU shape
this produced a malformed PDU or an empty one.

**Fix.** Removed the double split at all four sites — `ParseV3`'s plaintext
branch now leaves a fully usable `m.PDU`, and the handlers only unwrap the
decrypted buffer on the priv path. The now-meaningless `scopedContent` helper
was deleted. The two `encryptorFor` / `privParamsFor` helpers were factored out
so the "encrypt only when the flag says so" rule lives in one place — a
non-priv response is no longer encrypted.

This was found while writing the D1 tests, which is why it is in the same
commit: the downgrade tests could not have passed against the broken path.

### D3. `security.engine_store` was optional for authoritative engines

**Symptom.** `usm-translate` and `usm-gateway` own an authoritative engine and
must never let `engineBoots` decrease across a restart — that is what stops a
captured message from being replayed days later. The store path was optional,
so a config that omitted it ran happily with boots reset to a low value on
every restart, silently defeating the replay defence.

**Fix.** Engine-store requirement enforced in `Config.Validate` for
authoritative-engine modes. The escape hatch is explicit and loud:
`security.ephemeral_engine: true`, documented as testing-only. Flags mode
(plug-and-play) sets ephemeral automatically and logs a warning at startup,
because requiring a file path would break the two-command deployment.

### D4. Credential validation ran too late (or not at all)

- `auth_protocol: "shaa"` — a typo — used to surface as an obscure failure
  after listeners were up. Protocol parsing moved to a new leaf package
  `internal/securitylevel` (re-exported from `internal/usm` as type aliases so
  no call sites changed), which lets `config` validate names without an import
  cycle.
- A user with `auth_protocol: none` is now rejected in security-gate modes: it
  cannot satisfy the mode's contract.
- `authNoPriv` users were legal on paper but broken in practice. Fixed and
  covered.

### D5. Smaller items

- A pending-map entry leaked on one early-return path.
- `make test` now depends on a `fmt-check` target; an unformatted file used to
  slip into a green suite because nothing checked.

---

## Part 2 — Access policy (`3f68a3d`)

### Shape

One `access` section, identical key names to modbus-shield so an operator who
has met one appliance has met both:

```yaml
access:
  allow: ["10.8.0.0/24", "192.168.1.5"]
  rate_per_sec: 50
  read_only: true          # XOR
  write_policy:            # ...
    default: deny
    rules:
      - {oid: "1.3.6.1.4.1.99.1",   action: allow}
      - {oid: "1.3.6.1.4.1.99.1.9", action: deny}
```

Flags mode: `--allow` (repeatable), `--rate-per-sec`, `--read-only`,
`--write-default`, `--write-allow`/`--write-deny` (repeatable).
`--write-default` defaults to empty on purpose: a non-empty default would make
every flags-mode run build a default-deny policy with no rules and fail
validation.

`read_only` and `write_policy` are mutually exclusive. `allow` and
`rate_per_sec` are independent and optional.

### Denial behaviour is asymmetric — deliberately

| Denial | Behaviour | Reasoning |
|---|---|---|
| Client not on `allow` | silent drop | No presence disclosure; an error answer would amplify a flood. |
| Client over `rate_per_sec` | silent drop | The limit exists to absorb a flood, not converse with it. |
| SET outside the write policy | answered `notWritable` (v1 `noSuchName`) | The peer is authenticated and legitimate. A timeout would only make it retransmit into the policy forever. |

v1 has no status above 5, so `msg.ErrorStatusFor` maps `notWritable` to
`noSuchName` + error-index 1 (RFC 2576).

### Write-policy semantics

Deny-overrides, allow-must-cover, evaluated as a **set** (rule order is
irrelevant):

- any matching **deny** rejects the entire SET — one forbidden varbind is
  enough, because a write must never straddle an allowed and a forbidden
  subtree;
- an **allow** wins only when a single rule covers **every** requested object;
- otherwise `default` decides.

An undecodable or empty-varbind SET is denied: an unparseable write cannot be
authorized. Non-SET PDUs always pass.

OID matching is prefix-based on arc boundaries (`1.3.6.1.4.1.99` matches
`…99.5` but not `…9999`). Matching was extracted into a new leaf package
`internal/oidmatch`, shared with `notifyfilter` so the two can never drift.

### Scope per role — the policy follows the client address

| Role | `allow` / `rate_per_sec` | `read_only` / `write_policy` |
|---|---|---|
| `manager` | yes | yes |
| `gateway` (USM or TSM front leg) | yes | yes |
| `agent` (tunnel ingress) | **no** — tunnel frames carry no client address; warned at startup | **yes** — defense in depth at the device |
| any role, `passthrough` | yes | v1/v2c only — v3 crosses opaquely; warned, role-specific text |

That agent-side row is the one addition beyond modbus parity, and it is worth
calling out for review: **8 ingress sites, not 6.** The box next to the device
enforces the write half itself, so a compromised manager-side proxy still
cannot write through it. The refusal is answered *over the tunnel*, so the
manager sees `notWritable` rather than a timeout.

### Reload

`SIGHUP` swaps **the access policy only**, and that is the honest limit:

- the policy is read per datagram, so a swap applies to the next packet — no
  rebind, no dropped session, no re-discovery;
- SIGHUP gets its own `signal.Notify` channel; putting it on the shutdown
  context would stop the process;
- everything socket- or crypto-bound (tunnel, `security.users`, listeners,
  notification filters, metrics endpoints) is diffed and logged
  `(restart required)`, never silently ignored — an operator who edits
  `listen_addr` must not believe it took effect;
- an invalid file, or a policy that does not compile, **keeps the running
  policy**: a reload typo must never leave the box unprotected or wide open;
- flags mode has no file to re-read, so SIGHUP is a logged no-op there.

All three systemd units gained `ExecReload=/bin/kill -HUP $MAINPID`, so this is
`systemctl reload snmp-shield-gateway`.

### Metrics

Three counters were **appended** to `observ.CounterList()`:
`snmp_shield_acl_denied_total`, `snmp_shield_writes_denied_total`,
`snmp_shield_rate_limited_total`. Appended, not inserted: the SNMP health MIB
exposes counters as numbered rows in list order, so insertion would have
renumbered every existing row.

---

## Evidence

| Claim | Test |
|---|---|
| Downgrade refused, reports correct | `internal/usm/security_level_test.go` |
| Read-only → `notWritable`, device sees 0 SETs | `access_e2e_test.go` (gosnmp over USM gateway) |
| Off-list client gets silence; live holder swap | `access_e2e_test.go` |
| Subtree allow/deny incl. a straddling SET | `access_e2e_test.go` |
| Rate-limit burst | `access_e2e_test.go` |
| TSM front leg refuses writes, ids echoed | `internal/tsm/access_test.go` |
| **Agent-side** policy over the full usm-translate chain | `proxy_test.go` `TestRunAgentReadOnlyE2E` |
| Agent-side policy, TSM chain | `tsm_e2e_test.go` `TestTSMEndToEndAgentReadOnly` |
| Semantics, arc boundaries, undecodable SET, bucket cap | `internal/access/*_test.go` (88.5% cov) |
| Reload applies access, warns on the rest, keeps policy on a bad file | `internal/proxy/reload_test.go` |
| Loader accepts the documented YAML | `config_test.go` `TestLoadAccessYAML` |

Verification run after the final commit: `gofmt` clean · `make test` (full race
suite, 14 packages) · `go vet` darwin + `GOOS=linux` · `staticcheck` clean ·
`govulncheck` 0 reachable · smoke + two-proxy interop + USM gateway interop +
manager-gateway interop all PASS.

Also verified live with the real binary and real net-snmp: `snmpset` returned
`notWritable` under `read_only`, then succeeded (rc=0) after a SIGHUP that
removed it; the reload log showed the policy swap and `(restart required)` for a
changed `listen_addr`; an invalid file kept the running policy.

---

## Upgrade notes

Behaviour changes an existing deployment could hit:

1. **`security.engine_store` is now required** for `usm-translate` and
   `usm-gateway`. A config that started before will now fail validation with an
   explanatory error. Fix: point it at persistent storage, or set
   `security.ephemeral_engine: true` if you genuinely accept losing engine
   state (testing only).
2. **`auth_protocol: none` users are rejected** in security-gate modes.
3. The config loader is stricter about protocol names (`shaa` is now an error
   rather than a late failure).
4. Nothing existing becomes more permissive. The access section is opt-in: with
   no `access` block, a nil policy allows everything, so behaviour is unchanged
   until the section is added.

---

## Deliberately not done

Recorded so the next reviewer does not have to rediscover them. None are
regressions; all are pre-existing.

- **No `recover()` on network goroutines.** A panic in one session handler takes
  the process down. Defensible for a hardened appliance with a systemd
  `Restart=on-failure`, but it is a choice, not an oversight.
- **No session cap in the agent accept loop** — a local DoS surface for someone
  who can reach the tunnel port with valid PSKs.
- **`usm-manager-gateway` discovery blocks its single reader** and accepts
  Reports from any source. Tightening it conflicts with the HA
  follow-the-wire rule, so it needs a design decision rather than a patch.
- **Test coverage gaps**: `internal/observ` 0%, `cmd` 51.4%. `internal/proxy`
  reads 58.2% because the denominator includes `Run` and signal wiring that the
  tests reach through `runAgent`/`runManager`/`runGateway` instead.
- **TSM gateway interop cannot pass on macOS**: the system net-snmp has no
  DTLS/TSM and there is no GNU `timeout`. Environmental. Its "untrusted client
  rejected" line is a false positive there — do not read it as a passing check.

---

## Out of scope

**Single-box integration with modbus-shield is a separate project** and is not
tracked here. The access layer was still written with modbus parity in mind
(identical key names, identical denial semantics) so that one appliance could
later present one policy vocabulary — but that is a property of the policy
design, not pending work in this repository.
