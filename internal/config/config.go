// Package config loads per-instance configuration for the snmp-shield
// binary. One YAML file describes one proxy instance; the role is chosen
// by the subcommand (manager or agent) and validated accordingly.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/securitylevel"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"gopkg.in/yaml.v3"
)

// Role identifies which side of the secured line this instance serves.
type Role string

const (
	RoleManager Role = "manager" // clear leg faces SNMP managers
	RoleAgent   Role = "agent"   // clear leg faces real SNMP agents/devices
	// RoleGateway is the single-box USM gateway: a plain-UDP front leg
	// terminates SNMPv3 USM directly from standard managers (the proxy is
	// the authoritative engine) and authenticated requests are relayed as
	// clear v1/v2c to the legacy agent. No tunnel, no second proxy.
	RoleGateway Role = "gateway"
)

// Tunnel holds the secured-segment settings shared by both roles.
//
// The manager-side instance dials the tunnel (tunnel client); the
// agent-side instance listens (tunnel server). This keeps the agent side
// free to sit behind NAT/firewall egress-only setups.
type Tunnel struct {
	// Mode selects the tunnel transport: "dtls" (UDP) or "tls" (TCP).
	Mode string `yaml:"mode"`

	// DialAddrs lists the tunnel endpoints the manager role dials, most
	// preferred first (HA failover): the dialer walks the list starting
	// at the last-known-good endpoint. A single endpoint is a one-element
	// list. Required for the manager role.
	DialAddrs []string `yaml:"dial_addrs"`
	// ListenAddr is the tunnel endpoint the agent role binds.
	ListenAddr string `yaml:"listen_addr"`

	// PSKIdentity is the PSK identity presented/expected.
	PSKIdentity string `yaml:"psk_identity"`
	// PSK is the pre-shared key: "hex:..." (hex-encoded), "text:..."
	// (literal bytes) or bare (tried as hex, then as literal bytes).
	PSK string `yaml:"psk"`

	// PskCiphersuites selects the DTLS 1.2 PSK cipher suites for the
	// tunnel, most preferred first: "aes128-ccm-8" (default),
	// "aes256-ccm-8", "aes128-ccm", "aes128-gcm", "aes128-cbc" (full
	// RFC names accepted as aliases). Both sides must share at least
	// one suite. Empty = default.
	PskCiphersuites []string `yaml:"psk_ciphersuites"`

	// Mutual TLS settings (used for both "tls" and cert-based "dtls").
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
	// InsecureSkipVerify disables tunnel peer certificate verification
	// (TLS mode only). Never enable in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	KeepaliveSecs       int `yaml:"keepalive_secs"`
	MaxReconnectBackoff int `yaml:"max_reconnect_backoff_secs"`
	MaxFrameSize        int `yaml:"max_frame_size"`
}

// ManagerRole is the configuration for the manager-side instance: it
// listens for clear SNMP from managers, forwards over the tunnel, and
// relays device notifications arriving from the tunnel to a sink.
type ManagerRole struct {
	// ListenAddr is the clear SNMP request listener (managers connect here).
	ListenAddr string `yaml:"listen_addr"`
	// TrapSinkAddr is where notifications from the tunnel are delivered.
	TrapSinkAddr string `yaml:"trap_sink_addr"`
	// TrapListenAddr, when set, also accepts notifications from local
	// devices and ships them across the tunnel.
	TrapListenAddr string `yaml:"trap_listen_addr"`
}

// AgentRole is the configuration for the agent-side instance: it accepts
// tunnel connections, forwards requests to the real agent, and forwards
// device notifications to the manager side over the tunnel.
type AgentRole struct {
	// AgentAddr is the real SNMP agent (requests are forwarded here).
	AgentAddr string `yaml:"agent_addr"`
	// TrapListenAddr is the clear notification listener for devices.
	TrapListenAddr string `yaml:"trap_listen_addr"`
	// TrapSinkAddr, when set, receives notifications that arrive over the
	// tunnel (manager-side traps) as v2c datagrams. Used in USM translate
	// mode for the reverse trap direction.
	TrapSinkAddr string `yaml:"trap_sink_addr"`
	// TrapSinkCommunity is the community used in v2c notifications
	// delivered to TrapSinkAddr.
	TrapSinkCommunity string `yaml:"trap_sink_community"`
	// AgentCommunity is the v1/v2c community used toward the real agent
	// (TSM mode).
	AgentCommunity string `yaml:"agent_community"`
}

// GatewayRole is the configuration for the single-box USM gateway: the
// front leg is a plain-UDP SNMPv3 listener (the proxy is the authoritative
// engine toward standard managers); authenticated requests are relayed as
// clear v1/v2c to the legacy agent. No tunnel.
type GatewayRole struct {
	// ListenAddr is the SNMPv3 USM listener (managers connect here).
	ListenAddr string `yaml:"listen_addr"`
	// AgentAddr is the legacy SNMP agent (authenticated requests are
	// relayed here as clear v1/v2c).
	AgentAddr string `yaml:"agent_addr"`
	// TrapListenAddr, when set, accepts clear v1/v2c notifications from
	// the legacy agent/network and forwards them as authenticated v3 USM
	// notifications toward the manager subscribers.
	TrapListenAddr string `yaml:"trap_listen_addr"`
	// TrapSinkAddr, when set, is the manager's v3 USM trap receiver:
	// clear notifications accepted on TrapListenAddr are wrapped into
	// authenticated v3 USM notifications and delivered here.
	TrapSinkAddr string `yaml:"trap_sink_addr"`
	// AgentCommunity is the v1/v2c community used toward the legacy agent.
	AgentCommunity string `yaml:"agent_community"`
	// TrapSinkCommunity is the v1/v2c community used in clear
	// notifications delivered to TrapSinkAddr (manager-gateway mode:
	// the legacy manager's trap receiver).
	TrapSinkCommunity string `yaml:"trap_sink_community"`
}

// Security configures the SNMP message-level security mode (USM
// translate). When Mode is "usm-translate", the proxies speak SNMPv3
// authPriv to each other over the tunnel and translate to/from v1/v2c on
// the clear legs.
type Security struct {
	// Mode selects the message-level security: "passthrough" (default)
	// or "usm-translate".
	Mode string `yaml:"mode"`

	// Users is the list of USM users shared by both proxy sides.
	Users []UserCfg `yaml:"users"`

	// EngineID, when set, fixes this instance's SNMP engine ID; otherwise
	// one is generated and persisted in EngineStore.
	EngineID string `yaml:"engine_id"`
	// EngineStore is the path of the engine boots/state store. REQUIRED
	// whenever this instance is the authoritative engine (usm-translate,
	// usm-gateway): engineBoots must never decrease across restarts, or
	// the RFC 3414 replay window reopens. Only gateway modes that FOLLOW
	// a remote engine (usm-manager-gateway) need no store.
	EngineStore string `yaml:"engine_store"`
	// EphemeralEngine explicitly accepts losing the engine state on
	// restart. Testing and the no-YAML quick start only: a restart then
	// resets engineBoots, which weakens replay protection.
	EphemeralEngine bool `yaml:"ephemeral_engine"`

	// TrapCommunity is the community used in v2c notifications delivered
	// to local sinks (default "public").
	TrapCommunity string `yaml:"trap_community"`

	// TSMIdentities is the allow-list of peer certificate identities
	// (TSM mode): the peer leaf CN must be on this list. Empty allows
	// any certificate-authenticated peer.
	TSMIdentities []string `yaml:"tsm_identities"`
}

// NotifyFilter configures OID-based notification filtering at the relay
// ingress points: notifications whose trap OID does not pass the filter
// are dropped before they are relayed.
type NotifyFilter struct {
	// Action is "allow" (forward only matching OIDs, default) or "deny"
	// (drop matching OIDs).
	Action string `yaml:"action"`
	// Oids is the list of dotted OID prefixes (arc-boundary match).
	Oids []string `yaml:"oids"`
}

// Notifications groups notification handling settings.
type Notifications struct {
	Filter *NotifyFilter `yaml:"filter"`
}

// Access configures the request-leg access policy: which clients may talk
// to the proxy, how fast, and which objects they may write. It applies to
// REQUEST ingress only — the notification paths are governed by
// notifications.filter.
//
// Which parts apply where:
//   - manager role: the clear manager leg has a client address, so allow,
//     rate_per_sec and the write policy all apply.
//   - gateway role: the front leg (USM or TSM) is a client leg, so all
//     three apply.
//   - agent role: requests arrive over the trusted tunnel and carry no
//     client address, so only read_only/write_policy apply (defense in
//     depth for the device); allow/rate_per_sec are reported as ignored
//     at startup. A passthrough tunnel is opaque, so even the write
//     policy cannot see those requests.
type Access struct {
	// Allow is the client allow-list: bare IPs ("10.0.0.5") or CIDR
	// ranges ("10.8.0.0/24", IPv6 too). Empty allows every client.
	Allow []string `yaml:"allow"`
	// RatePerSec caps requests per client per second (a full second's
	// worth of burst is absorbed). 0 = unlimited.
	RatePerSec int `yaml:"rate_per_sec"`
	// ReadOnly refuses every SET with notWritable. Use the coarse switch
	// when nobody should write; use write_policy when some objects are
	// still writable.
	ReadOnly bool `yaml:"read_only"`
	// WritePolicy is the OID-scoped write policy. Mutually exclusive
	// with ReadOnly.
	WritePolicy *WritePolicyCfg `yaml:"write_policy"`
}

// WritePolicyCfg is the YAML shape of an OID-scoped write policy.
type WritePolicyCfg struct {
	// Default is the verdict for a write no rule covers: "deny" (default)
	// or "allow".
	Default string `yaml:"default"`
	// Rules are evaluated as a set (order is irrelevant): any matching
	// deny rejects the write, otherwise an allow must cover every
	// requested object.
	Rules []WriteRuleCfg `yaml:"rules"`
}

// WriteRuleCfg is one write-policy rule: a dotted OID subtree root and
// the verdict for writes inside it.
type WriteRuleCfg struct {
	OID    string `yaml:"oid"`
	Action string `yaml:"action"` // "allow" or "deny"
}

// MetricsRole configures the SNMP metrics interface: a small read-only
// SNMPv2c agent (health polling) and optional v2c event traps for tunnel
// lifecycle changes. This lets an SNMP-native monitoring system watch
// the proxy without the HTTP metrics endpoint.
type MetricsRole struct {
	// ListenAddr, when set, serves the SNMP health MIB (GET/GETNEXT)
	// on this UDP address.
	ListenAddr string `yaml:"listen_addr"`
	// Community is the SNMPv2c community for both the health MIB and
	// event traps (default "public").
	Community string `yaml:"community"`
	// BaseOID is the MIB root (default ".1.3.6.1.4.1.58427.1", IANA
	// PEN 58427 placeholder — set your own enterprise OID).
	BaseOID string `yaml:"base_oid"`
	// TrapSinkAddr, when set, receives v2c event traps (tunnel up/down,
	// HA failover) emitted on tunnel lifecycle changes.
	TrapSinkAddr string `yaml:"trap_sink_addr"`
}

// UserCfg is one USM user: protocols + passphrases. On the agent side,
// Community maps authenticated requests to the v1/v2c community used
// toward the real agent.
type UserCfg struct {
	Name           string `yaml:"name"`
	AuthProtocol   string `yaml:"auth_protocol"`
	AuthPassphrase string `yaml:"auth_passphrase"`
	PrivProtocol   string `yaml:"priv_protocol"`
	PrivPassphrase string `yaml:"priv_passphrase"`
	Community      string `yaml:"community"`
}

// Config is the full per-instance configuration.
type Config struct {
	Role          Role          `yaml:"-"`
	Tunnel        Tunnel        `yaml:"tunnel"`
	Manager       ManagerRole   `yaml:"manager"`
	Agent         AgentRole     `yaml:"agent"`
	Gateway       GatewayRole   `yaml:"gateway"`
	Security      Security      `yaml:"security"`
	Notifications Notifications `yaml:"notifications"`
	Access        Access        `yaml:"access"`
	Metrics       MetricsRole   `yaml:"metrics"`
}

// ValidateMetrics checks the SNMP metrics interface configuration.
func (c *Config) ValidateMetrics() error {
	m := c.Metrics
	if m.ListenAddr == "" && m.TrapSinkAddr == "" {
		return nil
	}
	if m.TrapSinkAddr != "" && m.ListenAddr == "" {
		// Traps only: no listener needed, but the source socket is the
		// trap listener... traps are sent from a dedicated socket in
		// that case; valid without ListenAddr.
		return nil
	}
	return nil
}

// TrapFilter builds the notification filter from the configuration. It
// returns nil (allow everything) when no filter is configured.
func (c *Config) TrapFilter() (*notifyfilter.Filter, error) {
	if c.Notifications.Filter == nil {
		return nil, nil
	}
	f := c.Notifications.Filter
	return notifyfilter.New(f.Action, f.Oids)
}

// AccessPolicy compiles the access section into a runtime policy. A
// zero-valued Access section yields a nil policy (allow everything), so
// callers can install the result unconditionally.
func (c *Config) AccessPolicy() (*access.Policy, error) {
	a := c.Access
	if len(a.Allow) == 0 && a.RatePerSec == 0 && !a.ReadOnly && a.WritePolicy == nil {
		// Nothing configured: a nil policy is the "no restriction" value
		// and keeps the reload path able to tell "configured" from "not".
		return nil, nil
	}
	var writes *access.WritePolicy
	switch {
	case a.ReadOnly && a.WritePolicy != nil:
		return nil, fmt.Errorf("access.read_only and access.write_policy are mutually exclusive")
	case a.ReadOnly:
		writes = access.NewReadOnly()
	case a.WritePolicy != nil:
		defaultAllow := false
		switch a.WritePolicy.Default {
		case "", "deny":
		case "allow":
			defaultAllow = true
		default:
			return nil, fmt.Errorf("access.write_policy.default: unknown value %q (want allow or deny)", a.WritePolicy.Default)
		}
		rules := make([]access.WriteRule, 0, len(a.WritePolicy.Rules))
		for i, r := range a.WritePolicy.Rules {
			if r.OID == "" {
				return nil, fmt.Errorf("access.write_policy.rules[%d]: oid is required", i)
			}
			var allow bool
			switch r.Action {
			case "", "deny":
			case "allow":
				allow = true
			default:
				return nil, fmt.Errorf("access.write_policy.rules[%d]: unknown action %q (want allow or deny)", i, r.Action)
			}
			rules = append(rules, access.WriteRule{OID: r.OID, Allow: allow})
		}
		wp, err := access.NewWritePolicy(defaultAllow, rules)
		if err != nil {
			return nil, err
		}
		writes = wp
	}
	return access.New(a.Allow, a.RatePerSec, writes)
}

// validateAccess checks the access section before the process starts: a
// bad allow entry or OID rule must never silently widen (or narrow) the
// policy at runtime.
func (c *Config) validateAccess() error {
	a := c.Access
	for _, e := range a.Allow {
		if e == "" {
			return fmt.Errorf("access.allow: empty entry")
		}
		if net.ParseIP(e) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(e); err != nil {
			return fmt.Errorf("access.allow: %q is neither an IP nor a CIDR range", e)
		}
	}
	if a.RatePerSec < 0 {
		return fmt.Errorf("access.rate_per_sec: must be >= 0 (0 = unlimited)")
	}
	if a.ReadOnly && a.WritePolicy != nil {
		return fmt.Errorf("access.read_only and access.write_policy are mutually exclusive (read_only refuses every write)")
	}
	if a.WritePolicy != nil {
		switch a.WritePolicy.Default {
		case "", "deny", "allow":
		default:
			return fmt.Errorf("access.write_policy.default: unknown value %q (want allow or deny)", a.WritePolicy.Default)
		}
		for i, r := range a.WritePolicy.Rules {
			if r.OID == "" {
				return fmt.Errorf("access.write_policy.rules[%d]: oid is required", i)
			}
			if err := access.ValidateOID(r.OID); err != nil {
				return fmt.Errorf("access.write_policy.rules[%d]: %w", i, err)
			}
			switch r.Action {
			case "", "allow", "deny":
			default:
				return fmt.Errorf("access.write_policy.rules[%d]: unknown action %q (want allow or deny)", i, r.Action)
			}
		}
		if len(a.WritePolicy.Rules) == 0 && a.WritePolicy.Default != "allow" {
			return fmt.Errorf("access.write_policy: no rules with default deny would block every write (use access.read_only instead)")
		}
	}
	// Compile once so validation and runtime can never disagree.
	if _, err := c.AccessPolicy(); err != nil {
		return fmt.Errorf("access: %w", err)
	}
	return nil
}

// DialEndpoints returns the tunnel endpoints the manager role dials, most
// preferred first.
func (c *Config) DialEndpoints() []string {
	return c.Tunnel.DialAddrs
}

// Defaults fills unset fields with sane values.
func (c *Config) Defaults() {
	if c.Tunnel.Mode == "" {
		c.Tunnel.Mode = "dtls"
	}
	if c.Tunnel.KeepaliveSecs <= 0 {
		c.Tunnel.KeepaliveSecs = 10
	}
	if c.Tunnel.MaxReconnectBackoff <= 0 {
		c.Tunnel.MaxReconnectBackoff = 30
	}
	if c.Tunnel.MaxFrameSize <= 0 {
		c.Tunnel.MaxFrameSize = 65536
	}
	if c.Security.Mode == "" {
		c.Security.Mode = "passthrough"
	}
	if c.Security.TrapCommunity == "" {
		c.Security.TrapCommunity = "public"
	}
	if c.Metrics.Community == "" {
		c.Metrics.Community = "public"
	}
	if c.Metrics.BaseOID == "" {
		c.Metrics.BaseOID = ".1.3.6.1.4.1.58427.1"
	}
}

// validateSecurityUsers checks the USM user database: protocol NAMES must
// parse (a typo used to silently delete the user at runtime, so every
// request from that manager failed with usmStatsUnknownUserNames), the
// passphrases those protocols need must be present, and privacy may not
// be requested without authentication.
func (c *Config) validateSecurityUsers() error {
	seen := make(map[string]bool, len(c.Security.Users))
	for _, u := range c.Security.Users {
		if u.Name == "" {
			return fmt.Errorf("security.users: user name is required")
		}
		if seen[u.Name] {
			return fmt.Errorf("security.users: duplicate user %q", u.Name)
		}
		seen[u.Name] = true
		ap, err := securitylevel.ParseAuthProtocol(u.AuthProtocol)
		if err != nil {
			return fmt.Errorf("security.users: user %s: auth_protocol: %w", u.Name, err)
		}
		pp, err := securitylevel.ParsePrivProtocol(u.PrivProtocol)
		if err != nil {
			return fmt.Errorf("security.users: user %s: priv_protocol: %w", u.Name, err)
		}
		if pp != securitylevel.PrivNone && ap == securitylevel.AuthNone {
			return fmt.Errorf("security.users: user %s: priv_protocol %q requires auth_protocol", u.Name, u.PrivProtocol)
		}
		if ap != securitylevel.AuthNone && u.AuthPassphrase == "" {
			return fmt.Errorf("security.users: user %s: auth_passphrase is required with auth_protocol %q", u.Name, u.AuthProtocol)
		}
		if pp != securitylevel.PrivNone && u.PrivPassphrase == "" {
			return fmt.Errorf("security.users: user %s: priv_passphrase is required with priv_protocol %q", u.Name, u.PrivProtocol)
		}
	}
	return nil
}

// requireAuthenticatedUsers rejects noAuthNoPriv users in the modes where
// this instance is the security gate: relaying traffic for an
// unauthenticated identity would defeat the point of the box. authNoPriv
// stays legal (authentication without encryption).
func (c *Config) requireAuthenticatedUsers() error {
	for _, u := range c.Security.Users {
		ap, err := securitylevel.ParseAuthProtocol(u.AuthProtocol)
		if err != nil {
			return fmt.Errorf("security.users: user %s: auth_protocol: %w", u.Name, err)
		}
		if ap == securitylevel.AuthNone {
			return fmt.Errorf("security.users: user %s: auth_protocol none is not allowed in %s mode (unauthenticated traffic must never be relayed)", u.Name, c.Security.Mode)
		}
	}
	return nil
}

// requireEngineStore enforces the anti-rollback contract: an
// authoritative engine must persist engineBoots. Memory-only state resets
// boots on every restart, which re-anchors the timeliness window and lets
// previously captured messages replay. EphemeralEngine is the explicit,
// documented escape hatch (quick start / tests).
func (c *Config) requireEngineStore() error {
	if c.Security.EngineStore != "" || c.Security.EphemeralEngine {
		return nil
	}
	return fmt.Errorf("security.engine_store is required for security.mode %s: engineBoots must never decrease across restarts (anti-rollback). Set security.engine_store to a persistent path (e.g. /var/lib/snmp-shield/engine.json), or set security.ephemeral_engine: true to accept losing engine state (testing only)", c.Security.Mode)
}

// Validate checks the configuration for the configured role.
func (c *Config) Validate() error {
	if _, err := c.TrapFilter(); err != nil {
		return fmt.Errorf("notifications.filter: %w", err)
	}
	if err := c.validateAccess(); err != nil {
		return err
	}
	if err := c.validateSecurityUsers(); err != nil {
		return err
	}
	if c.Metrics.BaseOID != "" {
		dotted := strings.TrimSuffix(strings.TrimPrefix(c.Metrics.BaseOID, "."), ".")
		if _, err := msg.EncodeOID(dotted); err != nil {
			return fmt.Errorf("metrics.base_oid: %w", err)
		}
		c.Metrics.BaseOID = "." + dotted
	}
	// Gateway role: single-box gateway — no tunnel. usm-gateway and
	// tsm-gateway terminate manager requests and relay them as clear
	// v1/v2c to a legacy agent. usm-gateway additionally supports
	// notification-only deployments (no request/agent leg): the
	// notification legs secure a manager leg instead.
	// usm-manager-gateway is the mirror: it fronts a legacy MANAGER and
	// re-issues its clear requests as authenticated v3 toward a
	// v3-capable agent.
	if c.Role == RoleGateway {
		switch c.Security.Mode {
		case "usm-gateway":
			// Either leg pair (or both): the request path (front
			// listener + legacy agent) and/or the notification path
			// (clear trap listener + manager's v3 trap receiver).
			hasRequest := c.Gateway.ListenAddr != "" && c.Gateway.AgentAddr != ""
			hasNotify := c.Gateway.TrapListenAddr != "" && c.Gateway.TrapSinkAddr != ""
			if !hasRequest && !hasNotify {
				return fmt.Errorf("security.mode usm-gateway requires gateway.listen_addr + gateway.agent_addr (request path) or gateway.trap_listen_addr + gateway.trap_sink_addr (notification path)")
			}
			if (c.Gateway.ListenAddr == "") != (c.Gateway.AgentAddr == "") {
				return fmt.Errorf("gateway.listen_addr and gateway.agent_addr must be configured together (request path)")
			}
			if (c.Gateway.TrapListenAddr == "") != (c.Gateway.TrapSinkAddr == "") {
				return fmt.Errorf("gateway.trap_listen_addr and gateway.trap_sink_addr must be configured together (notification path)")
			}
			if len(c.Security.Users) == 0 {
				return fmt.Errorf("security.users: usm-gateway needs at least one user")
			}
			if err := c.requireAuthenticatedUsers(); err != nil {
				return err
			}
			// The gateway IS the authoritative engine toward managers,
			// so its boots must survive restarts.
			return c.requireEngineStore()
		case "usm-manager-gateway":
			// The request path is required: legacy manager front leg +
			// real v3 agent. The trap legs are optional (v3 agent
			// notifications relayed as clear v2c to the manager).
			if c.Gateway.ListenAddr == "" {
				return fmt.Errorf("gateway.listen_addr is required (legacy manager front leg)")
			}
			if c.Gateway.AgentAddr == "" {
				return fmt.Errorf("gateway.agent_addr is required (real v3 agent)")
			}
			if len(c.Security.Users) == 0 {
				return fmt.Errorf("security.users: usm-manager-gateway needs at least one user (the v3 agent's credentials)")
			}
			// The AGENT is the authoritative engine here: the gateway
			// follows it and needs no engine store of its own.
			return c.requireAuthenticatedUsers()
		case "tsm-gateway":
			if c.Gateway.ListenAddr == "" {
				return fmt.Errorf("gateway.listen_addr is required")
			}
			if c.Gateway.AgentAddr == "" {
				return fmt.Errorf("gateway.agent_addr is required")
			}
			// The raw DTLS front leg is certificate-based: the gateway
			// presents a cert and verifies client certificates against
			// the CA.
			if c.Tunnel.CertFile == "" || c.Tunnel.KeyFile == "" {
				return fmt.Errorf("security.mode tsm-gateway requires tunnel.cert_file and tunnel.key_file")
			}
			if c.Tunnel.CAFile == "" {
				return fmt.Errorf("security.mode tsm-gateway requires tunnel.ca_file to verify client certificates")
			}
		default:
			return fmt.Errorf("gateway role requires security.mode usm-gateway, usm-manager-gateway or tsm-gateway, got %q", c.Security.Mode)
		}
		return nil
	}
	switch c.Role {
	case RoleManager, RoleAgent:
	default:
		return fmt.Errorf("unknown role %q", c.Role)
	}
	switch c.Tunnel.Mode {
	case "dtls", "tls":
	default:
		return fmt.Errorf("tunnel.mode must be dtls or tls, got %q", c.Tunnel.Mode)
	}
	if c.Tunnel.Mode == "dtls" && len(c.Tunnel.CertFile) == 0 && len(c.Tunnel.PSK) == 0 {
		return fmt.Errorf("tunnel: dtls needs either psk or certificate material")
	}
	if len(c.Tunnel.PSK) > 0 || len(c.Tunnel.PskCiphersuites) > 0 {
		// Validate ciphersuite names (tunnel package owns the mapping;
		// no import cycle since tunnel does not import config).
		if err := tunnel.ValidatePskCiphersuites(c.Tunnel.PskCiphersuites); err != nil {
			return fmt.Errorf("tunnel.psk_ciphersuites: %w", err)
		}
	}
	if c.Role == RoleManager {
		if c.Manager.ListenAddr == "" {
			return fmt.Errorf("manager.listen_addr is required")
		}
		if len(c.DialEndpoints()) == 0 {
			return fmt.Errorf("tunnel.dial_addrs is required for manager role (one or more ip:port endpoints, most preferred first)")
		}
	} else {
		if c.Agent.AgentAddr == "" {
			return fmt.Errorf("agent.agent_addr is required")
		}
		if c.Tunnel.ListenAddr == "" {
			return fmt.Errorf("tunnel.listen_addr is required for agent role")
		}
	}
	switch c.Security.Mode {
	case "passthrough", "usm-translate", "tsm", "usm-gateway", "tsm-gateway", "usm-manager-gateway":
	default:
		return fmt.Errorf("security.mode must be passthrough, usm-translate, tsm, usm-gateway, tsm-gateway or usm-manager-gateway, got %q", c.Security.Mode)
	}
	if c.Security.Mode == "usm-gateway" || c.Security.Mode == "tsm-gateway" || c.Security.Mode == "usm-manager-gateway" {
		return fmt.Errorf("security.mode %s is only valid with the gateway role", c.Security.Mode)
	}
	if c.Security.Mode == "usm-translate" {
		if len(c.Security.Users) == 0 {
			return fmt.Errorf("security.users: usm-translate needs at least one user")
		}
		if err := c.requireAuthenticatedUsers(); err != nil {
			return err
		}
		// Both sides terminate USM, so both must persist engine boots.
		if err := c.requireEngineStore(); err != nil {
			return err
		}
	}
	if c.Security.Mode == "tsm" {
		// TSM requires certificate-based tunnel endpoints: the server
		// presents a cert, the client verifies it (and vice versa).
		if c.Tunnel.CertFile == "" || c.Tunnel.KeyFile == "" {
			return fmt.Errorf("security.mode tsm requires tunnel.cert_file and tunnel.key_file")
		}
		if c.Role == RoleManager && c.Tunnel.CAFile == "" {
			return fmt.Errorf("security.mode tsm requires tunnel.ca_file on the agent side to verify client certificates")
		}
	}
	return nil
}

// Keepalive returns the keepalive interval.
func (c *Config) Keepalive() time.Duration {
	return time.Duration(c.Tunnel.KeepaliveSecs) * time.Second
}

// Backoff returns the maximum reconnect backoff.
func (c *Config) Backoff() time.Duration {
	return time.Duration(c.Tunnel.MaxReconnectBackoff) * time.Second
}

// PSKBytes parses the configured PSK into raw bytes. Supported forms:
// "hex:<hex>", "text:<literal>", or bare (hex first, then literal).
func (c *Config) PSKBytes() ([]byte, error) {
	s := c.Tunnel.PSK
	switch {
	case strings.HasPrefix(s, "hex:"):
		return hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	case strings.HasPrefix(s, "text:"):
		return []byte(strings.TrimPrefix(s, "text:")), nil
	case s == "":
		return nil, fmt.Errorf("tunnel.psk is empty")
	default:
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
		return []byte(s), nil
	}
}

// Load reads the YAML file at path and applies role-specific defaults.
func Load(path string, role Role) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{Role: role}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
