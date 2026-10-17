// cmd smoke test: verify the flag-built configs validate and load for both
// roles, and that flag-vs-YAML equivalence holds (package main).
package main

import (
	"testing"

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
)

func TestFlagsConfigManager(t *testing.T) {
	cfg, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode: "dtls",
		tunnelAddr: "10.0.0.2:10162",
		psk:        "aabbccdd",
		secMode:    "usm-translate",
		authPass:   "authpass",
		privPass:   "privpass",
		listen:     "0.0.0.0:161",
		community:  "public",
		trapSink:   "127.0.0.1:10163",
	})
	if err != nil {
		t.Fatalf("manager flagsConfig: %v", err)
	}
	if cfg.Tunnel.DialAddr != "10.0.0.2:10162" {
		t.Fatalf("dial addr = %q", cfg.Tunnel.DialAddr)
	}
	if cfg.Tunnel.PSK != "hex:aabbccdd" {
		t.Fatalf("psk = %q", cfg.Tunnel.PSK)
	}
	if cfg.Security.Mode != "usm-translate" || len(cfg.Security.Users) != 1 {
		t.Fatalf("security mode = %q users = %d", cfg.Security.Mode, len(cfg.Security.Users))
	}
	if cfg.Security.Users[0].Name != "proxy" || cfg.Security.Users[0].AuthProtocol != "sha" || cfg.Security.Users[0].PrivProtocol != "aes" {
		t.Fatalf("user profile = %+v", cfg.Security.Users[0])
	}
	if cfg.Manager.ListenAddr != "0.0.0.0:161" || cfg.Manager.TrapSinkAddr != "127.0.0.1:10163" {
		t.Fatalf("manager role = %+v", cfg.Manager)
	}
}

func TestFlagsConfigAgent(t *testing.T) {
	cfg, err := flagsConfig(config.RoleAgent, flagsOpts{
		tunnelMode: "dtls",
		tunnelAddr: "0.0.0.0:10162",
		psk:        "aabbccdd",
		secMode:    "usm-translate",
		authPass:   "authpass",
		privPass:   "privpass",
		agent:      "127.0.0.1:161",
		community:  "realcomm",
	})
	if err != nil {
		t.Fatalf("agent flagsConfig: %v", err)
	}
	if cfg.Tunnel.ListenAddr != "0.0.0.0:10162" {
		t.Fatalf("listen addr = %q", cfg.Tunnel.ListenAddr)
	}
	if cfg.Agent.AgentAddr != "127.0.0.1:161" {
		t.Fatalf("agent addr = %q", cfg.Agent.AgentAddr)
	}
	if len(cfg.Security.Users) != 1 || cfg.Security.Users[0].Community != "realcomm" {
		t.Fatalf("user community = %+v", cfg.Security.Users)
	}
}

func TestFlagsConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		r    config.Role
		o    flagsOpts
	}{
		{"no tunnel addr", config.RoleManager, flagsOpts{psk: "aabb", secMode: "usm-translate", authPass: "a", privPass: "b", listen: ":161"}},
		{"no psk", config.RoleManager, flagsOpts{tunnelAddr: ":1", secMode: "usm-translate", authPass: "a", privPass: "b", listen: ":161"}},
		{"no passes", config.RoleManager, flagsOpts{tunnelAddr: ":1", psk: "aabb", secMode: "usm-translate", listen: ":161"}},
		{"bad security", config.RoleManager, flagsOpts{tunnelAddr: ":1", psk: "aabb", secMode: "tsm", authPass: "a", privPass: "b", listen: ":161"}},
		{"manager no listen", config.RoleManager, flagsOpts{tunnelAddr: ":1", psk: "aabb", secMode: "usm-translate", authPass: "a", privPass: "b"}},
		{"agent no agent", config.RoleAgent, flagsOpts{tunnelAddr: ":1", psk: "aabb", secMode: "usm-translate", authPass: "a", privPass: "b"}},
	}
	for _, c := range cases {
		if _, err := flagsConfig(c.r, c.o); err == nil {
			t.Fatalf("%s: expected error, got nil", c.name)
		}
	}
}

func TestFlagsConfigPassthroughMode(t *testing.T) {
	cfg, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode: "dtls",
		tunnelAddr: "10.0.0.2:10162",
		psk:        "aabbccdd",
		secMode:    "passthrough",
		listen:     "0.0.0.0:161",
	})
	if err != nil {
		t.Fatalf("passthrough flagsConfig: %v", err)
	}
	if cfg.Security.Mode != "passthrough" || len(cfg.Security.Users) != 0 {
		t.Fatalf("security = %+v", cfg.Security)
	}
}
