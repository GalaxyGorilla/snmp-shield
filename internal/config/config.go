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

	"gopkg.in/yaml.v3"
)

// Role identifies which side of the secured line this instance serves.
type Role string

const (
	RoleManager Role = "manager" // clear leg faces SNMP managers
	RoleAgent   Role = "agent"   // clear leg faces real SNMP agents/devices
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

	// Mutual TLS settings (used for both "tls" and cert-based "dtls").
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
	// InsecureSkipVerify disables tunnel peer certificate verification
	// (TLS mode only). Never enable in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	KeepaliveSecs        int `yaml:"keepalive_secs"`
	MaxReconnectBackoff  int `yaml:"max_reconnect_backoff_secs"`
	MaxFrameSize         int `yaml:"max_frame_size"`
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
}

// Config is the full per-instance configuration.
type Config struct {
	Role    Role        `yaml:"-"`
	Tunnel  Tunnel      `yaml:"tunnel"`
	Manager ManagerRole `yaml:"manager"`
	Agent   AgentRole   `yaml:"agent"`
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
}

// Validate checks the configuration for the configured role.
func (c *Config) Validate() error {
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
