# Conformance: snmp-shield against other SNMP stacks

`internal/conformance` drives the **real built binary** with third-party SNMP
implementations as peers. The purpose is independence: our own tests are
written against our own encoders and decoders, so they can only prove
self-consistency. If we mis-encode `msgMaxSize` the same way in both, every
`internal/*` test still passes. A vendor stack has no such symmetry with us.

This file records what that independence found, what the vendors disagree
about, and what cannot be verified on this host.

## Peers

| Peer | Stack | Version here | Provisioning |
|---|---|---|---|
| `gosnmp` | Go, in-process | v1.45.0 | always available (module dependency) |
| `netsnmp` | net-snmp CLI | 5.6.2.1 (Apple) | system `snmp` package |
| `pysnmp` | pure Python | 7.1.30 | `make peers` (venv) |
| `node` | node `net-snmp` | 3.29.2 | `make peers` (npm) |
| `snmpd` | net-snmp agent | 5.6.2.1 (Apple) | system `snmpd` (agent-leg scenario) |
| `netsnmp-docker` | net-snmp CLI over **DTLS/TSM** | 5.9.3 (Debian) | Docker daemon (`make peers` builds the image) |

`make peers` runs `scripts/peers-setup.sh`; it exits 77 when nothing can be
provisioned. A peer with a missing toolchain **skips**, it never fails: this
repository has no CI and must stay green on a bare machine. `gosnmp` always
runs, so the matrix can never become empty.

## Covered today

| Scenario | What it proves |
|---|---|
| `TestUSMGatewayRequests` (get/getnext/getbulk/walk/set/multi-varbind/exception) | A standard v3 manager's wire format is understood; responses are acceptable to the vendor stack |
| `TestUSMGatewayRejections` (wrong user, wrong auth pass, wrong priv pass, clear v2c on a v3 leg) | The security gate really refuses, with the vendor-visible failure mode |
| `TestUSMGatewayEnginePersistence` | engineBoots increments across restarts and the vendor's cached engine state is re-synced, not wedged |
| `TestUSMGatewayNotificationIngress` (v2c trap, v1 trap translation, v2c inform confirmation) | Clear notifications are wrapped into v3 authPriv messages a vendor receiver accepts; informs are confirmed end-to-end |
| `TestUSMGatewayNotifyFilterWire` | A filtered trap is dropped on the wire, not merely logged |
| `TestUSMGatewayAccessPolicyWire` | `--read-only` refuses a SET on the wire while reads pass |
| `TestTranslateChainRequests` (v1 + v2c × get/getnext/set/trap, getbulk, inform) | Two-proxy chain: an untouched legacy manager keeps working across the PSK-DTLS tunnel; traps come out clear v2c on the far side; inform confirmation survives four hops |
| `TestTranslateChainAgentWritePolicy` | Device-side policy refuses a write and the refusal travels back through the tunnel instead of timing out; the device sees no SET |
| `TestManagerGatewayRealAgent` (real snmpd) | v3 **request generation**: RFC 3414 discovery, signed+encrypted requests, and parsing a real agent's answer; v3 trap and v3 inform reception, including the authoritative-inform handshake |
| `TestTSMGatewayVendorClient` (net-snmp 5.9 in Docker) | RFC 6353 **TSM**: a third-party client completes the DTLS handshake, presents a client certificate, and accepts our responses over `dtls:` — GET, GETNEXT, WALK, SET, plus a foreign-CA client being refused before anything reaches the device |
| `TestTSMGatewayVendorClientReadOnly` | A locally generated `notWritable` reaches the vendor client as an answer, not a timeout, and the device sees no SET |

The TSM scenarios are the only ones that need Docker. A host whose net-snmp
has no TLS (Apple's does not) would otherwise leave RFC 6353 verified only
against our own DTLS stack — which is exactly the self-consistency trap this
layer exists to avoid.

## Findings: real bugs the vendor matrix forced out

These were **our** bugs. Each is fixed and pinned by a regression test.

1. **Gateway modes silently ignored the access-policy flags.**
   `flagsConfig` returned early for the gateway role before calling
   `accessPolicy(...)`, so `--read-only`, `--allow`, `--rate-per-sec` and
   `--write-*` were parsed, accepted and thrown away for exactly the modes
   that face third-party clients. The startup log said `policy: none (allow
   everything)`. Pinned by
   `cmd/snmp-shield/main_test.go:TestFlagsConfigGatewayAccessPolicy` and the
   wire-level `TestUSMGatewayAccessPolicyWire`.

2. **Inform confirmations left from the wrong socket.**
   Both two-proxy managers replied to a relayed inform from the *request*
   listener instead of the *trap* listener that received the inform.
   gosnmp and pysnmp use connected UDP sockets, so the kernel discarded the
   answer and the inform timed out; net-snmp happened to tolerate it. Fixed
   in `internal/usm/translate_manager.go` and `internal/tsm/tsm_manager.go`
   (`notifyConn()`); pinned by
   `internal/usm/translate_manager_e2e_test.go:TestChainInformConfirmationSourceSocket`
   and `TestTranslateChainRequests/inform-round-trip-through-both-proxies`.

3. **Manager-gateway inform confirmations used a fresh msgID.** A v3 Response
   must echo the request's msgID: it is the transaction identifier.
   net-snmp, pysnmp and node silently dropped the answer and timed out;
   gosnmp does not validate the v3 header msgID, so a gosnmp-only test could
   never see it (measured: mutating only the msgID fails those three and
   passes gosnmp). Fixed by `buildV3Reply`/`buildV3Message` in
   `internal/usm/manager_gateway.go`; pinned by
   `TestManagerGatewayCompliantInform`.

4. **Manager-gateway could not receive informs from a compliant sender at
   all.** For confirmed notifications the **receiver** is the authoritative
   engine (RFC 3414 §2.2), so vendors probe for its engineID before sending.
   The trap leg had no engine, answered no discovery, and rejected the
   resulting inform as "unknown user". Traps were unaffected, which is why
   only inform traffic exposed it. Fixed by giving the trap leg its own
   `cache.EngineClock` (persistent when `security.engine_store` is set),
   answering discovery probes with a Report, checking the inform's
   boots/time against that clock, and answering with the announced engine
   state. Pinned by `TestManagerGatewayCompliantInform` and the vendor
   matrix (net-snmp, pysnmp, node, gosnmp).

5. **Responses carried the Reportable flag.** Our USM gateway and TSM gateway
   echoed the request's `msgFlags` verbatim, so every response — and every
   locally generated `notWritable` refusal — claimed to be a
   confirmed-class message. RFC 3412 §6.4 reserves the flag for
   requests/informs. This one is *not* vendor-caught: all four stacks
   tolerate it (measured: setting it on the inform confirmation changes
   nothing for net-snmp, pysnmp, node or gosnmp), which is why it survived
   until the flag was checked against the RFC. Fixed in
   `internal/usm/gateway.go` (`sendV3Response`) and
   `internal/tsm/tsm_gateway.go` (forwarded answers and refusals); pinned by
   `TestGatewayResponseIsUnconfirmedClass`,
   `TestTSMGatewayGet` and `TestTSMGatewayReadOnlyRefusesWrites`, and the
   cleared form is what the vendor TSM client above verifies.

## Findings: vendor divergences (not our bugs)

Recorded so nobody "fixes" the proxy to match one vendor. Adapters normalize
**presentation only**; protocol behaviour is never adapted.

- **Type names differ.** net-snmp prints `STRING`/`Timeticks`, pysnmp
  reports the textual convention (`DisplayString`) or concrete class
  (`Integer32`), gosnmp uses `OctetString`/`TimeTicks`. Adapters map these to
  the base SMI type; scenarios assert base types only.
- **net-snmp is the strict encoder.** Non-minimal INTEGER encodings that
  gosnmp tolerates (`msgMaxSize` as `FF FF`) are rejected with
  `Received bad msgMaxSize`. This class was found by net-snmp during earlier
  hardening and is pinned in `internal/msg/ber_test.go`.
- **net-snmp is the strict decoder.** It validates the v3 msgID, the echoed
  contextEngineID, securityName, engine boots/time and the security-level
  flags. gosnmp validates almost none of these; a gosnmp-only suite gives
  false confidence in exactly this area. Where net-snmp is *not* strict is
  instructive too: it (and pysnmp, node, gosnmp) all tolerate a Reportable
  flag on a response, so that defect had to be caught by reading RFC 3412,
  not by a peer (finding 5 above).
- **Inform authority.** net-snmp, pysnmp and node perform receiver-side
  discovery for informs (RFC-correct). gosnmp treats informs like traps and
  addresses them to its own engine. The proxy supports both: a message
  addressed to our engine is handled authoritatively, anything else is
  verified sender-authoritatively.
- **node `net-snmp` shapes.** GETBULK answers repeaters as one array per
  column (must be flattened); a PDU error-status arrives as
  `RequestFailedError` with `.status` set and an uppercase message
  (`NotWritable`), which is an *answer*, not a transport error; `subtree()`
  emits one callback per response PDU, so a walk must be accumulated before
  printing.
- **pysnmp 7 API.** `walk_cmd` is an async generator (awaiting it is the
  classic 7.x migration error), `bulk_cmd` is the GETBULK primitive,
  `send_notification` takes the notification type positionally and returns
  `(errorIndication, errorStatus, errorIndex, varbinds)`. AES/DES privacy
  requires the `cryptography` package.
- **gosnmp trap API.** `SendTrap` requires at least one varbind and does not
  add `snmpTrapOID.0` itself; a TimeTicks value must be `uint32`; v1 traps
  need `Enterprise`/`AgentAddress`/`GenericTrap`/`SpecificTrap`; a v3
  notification sender must set its own `AuthoritativeEngineID` or gosnmp
  tries to discover the *receiver* (which a trap listener correctly ignores).
- **net-snmp CLI noise and syntax.** MIB and persistent-store warnings on
  stderr are harmless and are filtered before classification. v1 traps use
  `AGENT ENTERPRISE AGENT-ADDR GENERIC SPECIFIC TIMETICKS`; v2c traps need an
  empty agent argument.
- **Apple net-snmp 5.6.2.1 `snmpd`.** `rouser` and `rwuser` are unknown
  tokens, and `createUser` only takes effect when `SNMP_PERSISTENT_DIR`
  points at a writable directory (otherwise the user silently never
  exists). The conformance fixture does both; the created user can read.

## Deliberate limits

- **No third-party TSM *receiver*.** The Docker peer is a client: net-snmp
  5.9's `snmptrapd` in `dtls:` mode never reads its socket, so it cannot
  receive our TSM notifications. Notification wrapping stays verified by
  `internal/tsm` and `scripts/tsm-sink` (our own sink). The request direction
  — where the echo rules, the certificate gate and the response format are
  judged by a vendor — is covered.
- **Docker required for the TSM scenarios.** Without a running daemon they
  skip. `scripts/interop-gateway-tsm.sh` remains the shell-level equivalent
  for hosts that have a TLS-enabled net-snmp installed directly (rc 77 when
  they do not).
- **No vendor v3 trap *receiver*.** No peer here offers a configurable USM
  trap receiver with a known engine, so notification *content* is verified
  by `testkit.V3Sink` (gosnmp `TrapListener`). The sending side of every
  notification test is a real vendor stack, which is where the format
  surprises live.
- **No syslog/SNMPv1 trap receiver matrix.** v1 trap *sending* is covered
  (translated and relayed); a vendor v1 receiver adds nothing the parser
  tests do not already pin.

## What a green matrix means

- Every peer's requests and notifications are accepted by the proxy, and the
  proxy's answers are accepted by the peer, on wire format alone.
- Refusals happen in the vendor-visible way (timeout vs. error status), not
  merely in our metrics.
- The legacy side of every mode keeps speaking its original protocol.

It does **not** mean every MIB or every optional PDU is covered. The matrix
uses a tiny fixed MIB (`sysDescr.0`, `sysObjectID.0`, a test subtree) because
the assertions are about protocol behaviour, not data.
