# Deployment examples

Copy-paste walkthroughs for every supported deployment. Each example is
self-contained: it names the mode, the commands, and what to point where.
Config-file templates for every example live in [`configs/`](../configs/).

| Example | Deployment | What it protects |
|---|---|---|
| [two-proxy-usm](two-proxy-usm.md) | Two proxy boxes between manager and agent | The long-haul line (v3 authPriv between proxies, legacy v2c on both local legs) |
| [two-proxy-tsm](two-proxy-tsm.md) | Two proxy boxes, certificate-based | Same, with RFC 5591 TSM instead of PSK+USM |
| [gateway-usm](gateway-usm.md) | One box in front of a legacy agent | The agent itself: standard v3 managers talk to the gateway, unauthenticated traffic never reaches the device |
| [gateway-tsm](gateway-tsm.md) | One box, DTLS front leg | Same, with SNMP-over-DTLS (RFC 6353) certificate clients |
| [usm-manager](usm-manager.md) | One box in front of a manager | The manager leg: legacy device traps/informs are wrapped into authenticated v3 toward the manager (usm-gateway, notification-only) |
| [ha-two-proxy](ha-two-proxy.md) | Two proxy pairs, redundant agent side | Adds failover: the manager proxy dials a list of agent-side replicas and shares engine state |

Which one do I want?

- Devices can't do SNMPv3, and you control both ends → **two-proxy-usm**.
- Same, but you prefer certificates over PSKs → **two-proxy-tsm**.
- You can only put a box next to the **agent** (managers are off-limits,
  or you want one box per site) → **gateway-usm**.
- You can only put a box next to the **manager** → **usm-manager**
  (usm-gateway with only the notification legs).
- Redundancy matters (the agent-side box must survive failure) →
  **ha-two-proxy**.
