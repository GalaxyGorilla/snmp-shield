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
| `snmpd59` | net-snmp agent (Docker) | 5.9.3 (Debian) | Docker daemon (`make peers` builds the image) |
| `netsnmp59` | net-snmp CLI (clear legs) | 5.9.3 (Debian, Docker) | Docker daemon (`make peers` builds the image) |
| `netsnmp-docker` | net-snmp CLI over **DTLS/TSM** | 5.9.3 (Debian) | Docker daemon (`make peers` builds the image) |
| `snmptrapd` | net-snmp v3 notification **receiver** | 5.9.3 (Debian, Docker) | Docker daemon (`make peers` builds the image) |

Two net-snmp **agents** back the manager-gateway scenarios: the host's
`snmpd` (Apple 5.6.2.1) and the `snmpd` in the Debian image (5.9.3). Both run
the same suite, so a proxy behaviour that only one release accepts is a
finding rather than an assumption. They are not interchangeable fixtures:
5.9 refuses every request with `AuthorizationError` until an access-control
directive (`rouser`) exists, while 5.6 rejects `rouser` as an unknown token
and grants the created user access implicitly — see the divergences below.

Two net-snmp **CLI** peers run the *same* adapter (`test/peers/peer_netsnmp.py`):
the host CLI is Apple's 5.6.2.1 (2010) and the container is a current 5.9.3.
A disagreement between them is a finding about net-snmp or about us, never an
adapter difference. The container peer needs the fixture to bind a routable
address (`peerFront`) because a container cannot reach the host's loopback;
the adapter rewrites a loopback target to `host.docker.internal`.

`make peers` runs `scripts/peers-setup.sh`; it exits 77 when nothing can be
provisioned. A peer with a missing toolchain **skips**, it never fails: this
repository has no CI and must stay green on a bare machine. `gosnmp` always
runs, so the matrix can never become empty.

For a release, run `make conformance-required` instead
(`CONFORMANCE_REQUIRED=1`): every environment skip then becomes a failure,
because "all peers green" on a host without Docker, pysnmp or node means
gosnmp alone ran. A vendor limitation (`KindUnsupported` — the stack cannot
express the operation) still skips, and a source-scan test fails if a new
`t.Skip` bypasses the gate.

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
| `TestPassthroughChainNotifications` (both directions × trap + inform, five peers) | The opaque mode's notification legs, which no vendor had ever exercised: a vendor's trap/inform crosses the PSK-DTLS tunnel and the far-side sink receives it, and the inform's confirmation travels all the way back to the vendor's own sender socket |
| `TestPassthroughChainKeepsTheWireFormat` | The sink gets the device's own community and varbind values, not a re-encoding — the property that separates passthrough from the translating modes |
| `TestManagerGatewayRealAgent` (real snmpd, 5.6.2.1 and 5.9.3) | v3 **request generation**: RFC 3414 discovery, signed+encrypted requests, and parsing a real agent's answer — against both a 2010 host build and a current release; v3 trap and v3 inform reception, including the authoritative-inform handshake |
| `TestTSMGatewayVendorClient` (net-snmp 5.9 in Docker) | RFC 6353 **TSM**: a third-party client completes the DTLS handshake, presents a client certificate, and accepts our responses over `dtls:` — GET, GETNEXT, WALK, SET, plus a foreign-CA client being refused before anything reaches the device |
| `TestTSMGatewayVendorClientReadOnly` | A locally generated `notWritable` reaches the vendor client as an answer, not a timeout, and the device sees no SET |
| `TestUSMGatewayVendorTrapReceiver` | A **vendor** v3 trap receiver (`snmptrapd` 5.9) verifies and decrypts our wrapped trap and logs the payload varbind — every vendor stack as the sending side |
| `TestUSMGatewayVendorInformReceiver` | The wrapped inform is **confirmed by a vendor receiver** and the confirmation travels back to the device: the sender's own `snmpinform`/`inform` exits successfully |

Docker scenarios: the TSM client, the 5.9 clear-leg peer, the 5.9 **agent**
and the `snmptrapd` receiver. A host whose net-snmp has no TLS (Apple's does not)
would otherwise leave RFC 6353 verified only against our own DTLS stack —
which is exactly the self-consistency trap this layer exists to avoid. The
same trap applies to notifications: without `snmptrapd`, every "did the
manager accept our v3 trap?" assertion ran through `testkit.V3Sink`, which
is written against our own `msg` package and therefore accepts whatever we
emit (finding 6 is what that cost).

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

6. **USM gateway wrapped informs sender-authoritatively, so a strict
   receiver never confirmed them.** Traps and informs disagree about the
   authoritative engine (RFC 3414 §2.2): a trap names the **sender's**
   engine, an inform must name the **receiver's** (the sender discovers it
   first). The notification path used one wrap for both, naming our own
   engine. gosnmp's `TrapListener` and `testkit.V3Sink` are lenient — both
   localize keys to whatever engineID the message carries, so they accepted
   it — while net-snmp 5.9's `snmptrapd` answers only when it is the
   addressed engine and otherwise drops the inform in silence. The device
   then retransmits into a timeout. Proven on the wire: an inform sent to a
   fresh `snmptrapd` timed out; the *same* inform delivered immediately
   after a trap from the same engine was accepted, because the trap had
   taught the receiver our engine state. Fixed with `ensureSinkEngine`
   (RFC 3414 §4 discovery probe on a dedicated socket, 60s cache) and a
   per-engine wrap in `buildNotif` (`internal/usm/gateway.go`); traps keep
   the sender-authoritative path unchanged. Pinned by
   `internal/usm/gateway_inform_engine_test.go` (asserts the inform's
   msgAuthoritativeEngineID/boots/time are the sink's and that its digest
   verifies with sink-localized keys, and that a trap still names our own
   engine and performs **no** discovery) and by
   `TestUSMGatewayVendorInformReceiver`. If discovery fails the proxy logs a
   warning and falls back to the sender-authoritative wrap, so a receiver
   that does not answer discovery is not made worse. A **verified** answer
   from the sink also re-anchors the cache — including the
   `usmStatsNotInTimeWindows` Report a restarted receiver sends — so a
   receiver restart is followed on the next inform rather than after the
   60s discovery TTL (`TestGatewayFollowsSinkRestartFromResponse`).

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
- **node `net-snmp` units.** Its `timeout` option is milliseconds while the
  peer contract is seconds; the adapter previously passed the contract value
  through, giving every node call a 3 ms budget. Loopback answers beat it,
  so only a round trip through a proxy (an inform confirmation) exposed it.
  That was an **adapter** bug, not a vendor behaviour: fixed in
  `peer_node.js`, not worked around in a scenario.
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
- **net-snmp `snmpd` access control differs by release.** Apple's 5.6.2.1
  rejects `rouser`/`rwuser` as unknown tokens and a `createUser`-only agent
  serves the user; 5.9.3 answers `AuthorizationError` for every request and
  logs "no access control information configured" until an access-control
  directive is present (the fixture uses `rouser`, i.e. read-only, so the
  SET scenario still expects a refusal). Both also require a writable
  `SNMP_PERSISTENT_DIR`, otherwise `createUser` silently never exists. This
  is a fixture portability rule, not a proxy difference — a 5.9 agent
  without `rouser` makes every request look like our bug.
- **`snmpd` readiness must be judged on the PDU, not the socket.** gosnmp
  returns a packet with `err == nil` for an error-status answer, so a
  transport-only readiness probe declared an `AuthorizationError` agent
  ready and pushed the failure into the proxy assertions. The fixture now
  requires `pkt.Error == NoError`.

- **Address family is not vendor-driven.** No peer in the matrix can be
  pointed at an IPv6 port through the peer contract: net-snmp builds its own
  `udp6:`/`dtls:` URLs and the Docker peers reach the host only by the IPv4
  bridge name. IPv6 deployments are pinned by real sockets on `[::1]` per mode
  (`internal/usm/ipv6_e2e_test.go`, `internal/tsm/gateway_ipv6_test.go`,
  `internal/proxy`), which is the right oracle for transport — but a
  vendor-specific v6 quirk would not be caught here.

## Deliberate limits

- **No third-party TSM *receiver*.** The Docker peer is a client: net-snmp
  5.9's `snmptrapd` in `dtls:` mode never reads its socket, so it cannot
  receive our TSM notifications. Notification wrapping stays verified by
  `internal/tsm` and `scripts/tsm-sink` (our own sink). The request direction
  — where the echo rules, the certificate gate and the response format are
  judged by a vendor — is covered.
- **Docker required for the TSM scenarios and the current agent.** Without a
  running daemon they skip; the *host* `snmpd` scenarios still run, so the
  agent leg degrades to the OS release rather than disappearing.
  `scripts/interop-gateway-tsm.sh` remains the shell-level equivalent for
  hosts that have a TLS-enabled net-snmp installed directly (rc 77 when they
  do not).
- **The vendor v3 receiver still cannot be a *peer*.** `snmptrapd` is not
  driven through the peer contract (it is a receiver, not a client, and it
  needs to be told our engineID before we start). `trapd_test.go` starts it
  directly and reads its log, which is enough: the log is emitted only after
  USM verification and decryption succeed.
- **`snmptrapd` needs the sender's engine registered for traps and its own
  for informs.** `createUser -e 0x<engineID>` localizes the user's keys to
  that engine, `createUser` without `-e` localizes them to the receiver's
  own engine. A fixture that registers only one of the two forms looks like
  a proxy bug: traps become invisible, or informs stop being answered. Both
  lines are in the fixture's config, and the two tests exercise them
  separately.
- **No syslog/SNMPv1 trap receiver matrix.** v1 trap *sending* is covered
  (translated and relayed); a vendor v1 receiver adds nothing the parser
  tests do not already pin.

## Docker fixtures: let docker assign the host port

Both container fixtures (`snmptrapd`, and the 5.9 `snmpd` v3 agent) used to
probe a free UDP port, then publish it with `-p 127.0.0.1:<port>:…`. That is a
TOCTOU race between our probe and the daemon's bind: a second fixture probing
in the gap can be handed a port that docker is about to take. It surfaced
once, under full-suite load, as `usm gateway: trap listener: listen udp
0.0.0.0:<port>: bind: address already in use` — a product-looking failure
caused entirely by the fixture.

Both now publish `-p 127.0.0.1::<container-port>/udp` and read the assigned
port back from `docker port <name> <port>/udp` (`publishedLoopback`, which
fails loudly when the mapping is missing rather than letting a notification
travel into the void). The kernel assigns the port at publish time, so no
other fixture can have claimed it in between.

## Fixture gotcha: a readiness probe writes a byte

`waitFront`/`UDPBound` decides whether a UDP leg is bound by writing a single
`0x00` byte and watching for `ECONNREFUSED` (a closed UDP port only reports the
error on the *next* operation). On a request leg the proxy answers or ignores
it; on a **notification** leg that byte is a datagram arriving at the trap
listener. With `passthrough` forwarding bytes verbatim it reached the far-side
sink as an undecodable "notification", which made the first
`TestPassthroughChainNotifications` runs look like a relay bug.

The fix is in the product, not the harness: a trap listener carries
notifications and nothing else, so both passthrough ingresses now drop a
datagram that does not parse as a trap or inform (the translating modes always
did). The probe byte is harmless — and the check is worth having anyway,
because a misdirected request or a scanner datagram on the trap port would
otherwise be handed to the sink as an event the device never fired.

## What a green matrix means

- Every peer's requests and notifications are accepted by the proxy, and the
  proxy's answers are accepted by the peer, on wire format alone.
- Refusals happen in the vendor-visible way (timeout vs. error status), not
  merely in our metrics.
- The legacy side of every mode keeps speaking its original protocol.

It does **not** mean every MIB or every optional PDU is covered. The matrix
uses a tiny fixed MIB (`sysDescr.0`, `sysObjectID.0`, a test subtree) because
the assertions are about protocol behaviour, not data.
