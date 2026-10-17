// Package config loads per-instance configuration for the snmp-proxy
// binary. One YAML file describes one proxy instance; the role is chosen
// by the subcommand (manager or agent) and validated accordingly.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
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

	// DialAddr is the tunnel endpoint the manager role dials.
	DialAddr string `yaml:"dial_addr"`
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
	// EngineStore is the path of the engine boots/state store.
	EngineStore string `yaml:"engine_store"`

	// TrapCommunity is the community used in v2c notifications delivered
	// to local sinks (default "public").
	TrapCommunity string `yaml:"trap_community"`

	// TSMIdentities is the allow-list of peer certificate identities
	// (TSM mode): the peer leaf CN must be on this list. Empty allows
	// any certificate-authenticated peer.
	TSMIdentities []string `yaml:"tsm_identities"`
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
	Role     Role        `yaml:"-"`
	Tunnel   Tunnel      `yaml:"tunnel"`
	Manager  ManagerRole `yaml:"manager"`
	Agent    AgentRole   `yaml:"agent"`
	Gateway  GatewayRole `yaml:"gateway"`
	Security Security    `yaml:"security"`
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
}

// Validate checks the configuration for the configured role.
func (c *Config) Validate() error {
	// Gateway role: single-box gateway — no tunnel. The front leg
	// terminates SNMP security directly from third-party clients:
	// usm-gateway (plain-UDP SNMPv3 USM) or tsm-gateway (raw SNMP-over-
	// DTLS per RFC 6353); authenticated requests are relayed as clear
	// v1/v2c to the legacy agent.
	if c.Role == RoleGateway {
		if c.Gateway.ListenAddr == "" {
			return fmt.Errorf("gateway.listen_addr is required")
		}
		if c.Gateway.AgentAddr == "" {
			return fmt.Errorf("gateway.agent_addr is required")
		}
		switch c.Security.Mode {
		case "usm-gateway":
			if len(c.Security.Users) == 0 {
				return fmt.Errorf("security.users: usm-gateway needs at least one user")
			}
			for _, u := range c.Security.Users {
				if u.Name == "" {
					return fmt.Errorf("security.users: user name is required")
				}
				if u.AuthProtocol == "" || u.PrivProtocol == "" {
					return fmt.Errorf("security.users: user %s needs auth_protocol and priv_protocol", u.Name)
				}
			}
		case "tsm-gateway":
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
			return fmt.Errorf("gateway role requires security.mode usm-gateway or tsm-gateway, got %q", c.Security.Mode)
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
		if c.Tunnel.DialAddr == "" {
			return fmt.Errorf("tunnel.dial_addr is required for manager role")
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
	case "passthrough", "usm-translate", "tsm", "usm-gateway", "tsm-gateway":
	default:
		return fmt.Errorf("security.mode must be passthrough, usm-translate, tsm, usm-gateway or tsm-gateway, got %q", c.Security.Mode)
	}
	if c.Security.Mode == "usm-gateway" || c.Security.Mode == "tsm-gateway" {
		return fmt.Errorf("security.mode %s is only valid with the gateway role", c.Security.Mode)
	}
	if c.Security.Mode == "usm-translate" {
		if len(c.Security.Users) == 0 {
			return fmt.Errorf("security.users: usm-translate needs at least one user")
		}
		for _, u := range c.Security.Users {
			if u.Name == "" {
				return fmt.Errorf("security.users: user name is required")
			}
			if u.AuthProtocol == "" || u.PrivProtocol == "" {
				return fmt.Errorf("security.users: user %s needs auth_protocol and priv_protocol", u.Name)
			}
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
