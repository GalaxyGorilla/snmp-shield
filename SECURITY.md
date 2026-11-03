# SNMP Shield security model

SNMP Shield is a security boundary around legacy SNMP devices and managers. It
reduces exposure; it does not make an untrusted device, host, or clear network
segment trustworthy.

Start with [`README.md`](README.md) for deployment shapes,
[`examples/operations.md`](examples/operations.md) for day-2 operation,
[`TESTING.md`](TESTING.md) for the evidence and release gates, and
[`CONFORMANCE.md`](CONFORMANCE.md) for independent-peer results.

## Protected assets

- SNMPv3 USM authentication/encryption termination on gateway front legs, and
  RFC 6353 TSM/DTLS termination on TSM gateway front legs.
- The two-proxy tunnel: confidentiality, peer authentication and frame
  integrity on the secured segment.
- Per-agent isolation in an `agents:` gateway: a client of one listener can
  never reach another agent, and one entry's policy never gates another.
- Access policy: client allow-list, per-client rate limit, read-only and
  OID-scoped write policy, plus notification filtering.
- USM engine state and anti-rollback: persisted `engineBoots`, a monotonic
  timeliness window, and the per-agent engine store.
- Notification authority: traps are sender-authoritative, informs are
  receiver-authoritative, and a trap sink's engine is discovered before an
  inform is wrapped.
- Integrity of the running policy across `SIGHUP`; invalid reloads keep the
  last valid policy.
- No secrets in logs, metrics, `/status`, the SNMP health MIB, or error text.

## Trust boundaries

The appliance host, configuration file, administrators, private keys and
issuing CAs are trusted. The clear SNMP legs next to a legacy agent or manager
are **not** authenticated by the proxy; physically protect or isolate those
segments, exactly as the legacy protocol expects.

In the two-proxy shape, the tunnel protects the middle network; the local clear
legs remain clear. In a one-box gateway, the proxy terminates standard SNMPv3
USM or TSM/DTLS toward the client and relays clear v1/v2c to the device; the
device leg is trusted at the network layer. A manager-side gateway is the
reverse: clear v2c from the legacy manager, authenticated v3 toward the real
agent.

Client IP allow-lists are network policy, not cryptographic identity. Use USM
authPriv, TSM/DTLS, or the two-proxy tunnel when identity must survive NAT,
shared hosts, or an untrusted network. v1/v2c communities on a clear leg are
not security identities and must not be treated as such.

The legacy device and all wire input are treated as malformed or hostile, but a
compromised device can still return plausible false data.

## Enforced controls

- USM authPriv (SHA/AES by default; MD5/DES only for legacy compatibility) and
  explicit rejection of weaker security levels on gateway front legs.
- RFC 6353 TSM/DTLS with certificate verification and an identity allow-list.
- PSK-DTLS or TLS two-proxy tunnel, with certificate/PSK verification, frame
  integrity, keepalive and failover.
- RFC 3414 engine discovery, key localization, boots/time anti-replay and
  persisted engine state (memory-only engines require an explicit opt-in).
- Per-role access policy and write-policy semantics: deny-overrides,
  allow-must-cover, fail-closed on an undecodable SET.
- Per-entry isolation for `agents:`: independent listener, upstream, access
  holder, security/engine state, optional TLS and trap legs.
- Notification filtering at the relay ingress, and informs confirmed end to
  end (including receiver-side discovery).
- Front-door session caps (`tunnel.max_sessions`), per-client and shared rate
  limits, bounded pending tables and timeouts.
- Atomic policy snapshots on `SIGHUP`; listener/security/TLS changes are
  reported as restart-required, never silently ignored.
- Readiness only after every listener binds; `/status` exposes the active
  config revision/hash, per-entry readiness and reload result without secrets.
- Hardened systemd units, watchdog, graceful shutdown, structured logs,
  Prometheus metrics and an SNMP health MIB.
- Panic isolation around every per-datagram/frame handler.

Policy denials are enforced before forwarding. Off-list and over-rate clients
are dropped silently; a refused write is answered `notWritable` (v1
`noSuchName`) so the manager does not retransmit into a timeout.

## Deliberate limits

- SNMP Shield is not a firewall, IDS, malware scanner, SNMP router or
  general-purpose proxy forwarder.
- Clear v1/v2c legs are unauthenticated by design; the proxy protects the
  boundary it terminates, not the legacy wire.
- One security mode per process. Mixed modes per `agents:` entry are separate
  instances.
- Multi-agent over the two-proxy tunnel is closed: the tunnel frame has no
  agent selector, and `tunnel.dial_addrs` is failover for one logical agent.
  There is no routing by community, context or OID.
- A shared trap listener is optional; per-entry trap legs are the supported
  shape.
- TSM notifications have no third-party receiver in the test matrix (net-snmp's
  `snmptrapd` cannot receive DTLS); TSM notification behavior is pinned by our
  own DTLS sink and wire tests.
- Rate limits reduce abuse but cannot guarantee availability under host,
  network or upstream-device exhaustion.
- Certificate issuance, revocation, rotation and hardware key protection are
  deployment responsibilities.
- Real hardware, external review and regulatory certification remain separate
  validation work.

See [`docs/security-hardening.md`](docs/security-hardening.md) for the
defect-by-defect hardening review, access-policy semantics and the evidence.

## Release security gate

```sh
make verify               # format, race suite, build and vet
make conformance-required # every vendor peer must run, not skip
make security             # staticcheck, govulncheck, SBOM and HIGH+ gate
```

`make sbom` writes SPDX and CycloneDX documents to `dist/`.
`make vulnscan` matches the SBOM against NVD/GHSA/OSV and fails on HIGH or
above.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** function for this
repository. Include the affected role/mode, configuration shape, a
reproduction, the expected policy and the observed wire behavior. Do not attach
production credentials, USM passphrases, PSKs, private keys, or packet captures
containing customer data.
