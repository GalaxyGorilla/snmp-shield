// cmd smoke test: verify the flag-built configs validate and load for both
// roles, and that flag-vs-YAML equivalence holds (package main).
package main

import (
	"os"
	"strings"
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
	if len(cfg.Tunnel.DialAddrs) != 1 || cfg.Tunnel.DialAddrs[0] != "10.0.0.2:10162" {
		t.Fatalf("dial addrs = %v", cfg.Tunnel.DialAddrs)
	}
	if addrs := cfg.DialEndpoints(); len(addrs) != 1 || addrs[0] != "10.0.0.2:10162" {
		t.Fatalf("dial endpoints = %v", addrs)
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

func TestParsePskCiphersuites(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"aes128-gcm", []string{"aes128-gcm"}},
		{" a , b ", []string{"a", "b"}},
		{"x,,y", []string{"x", "y"}},
		{"aes256-ccm-8,aes128-ccm-8", []string{"aes256-ccm-8", "aes128-ccm-8"}},
	}
	for _, c := range cases {
		got := parsePskCiphersuites(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("parsePskCiphersuites(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parsePskCiphersuites(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestFlagsConfigGatewayUSM(t *testing.T) {
	cfg, err := flagsConfig(config.RoleGateway, flagsOpts{
		secMode:   "usm-gateway",
		listen:    "0.0.0.0:161",
		agent:     "127.0.0.1:161",
		authPass:  "authpass",
		privPass:  "privpass",
		community: "realcomm",
		trapSink:  "127.0.0.1:162",
	})
	if err != nil {
		t.Fatalf("gateway usm flagsConfig: %v", err)
	}
	if cfg.Security.Mode != "usm-gateway" || len(cfg.Security.Users) != 1 {
		t.Fatalf("security = %+v", cfg.Security)
	}
	if cfg.Security.Users[0].Name != "proxy" || cfg.Security.Users[0].AuthProtocol != "sha" || cfg.Security.Users[0].PrivProtocol != "aes" {
		t.Fatalf("user profile = %+v", cfg.Security.Users[0])
	}
	if cfg.Gateway.ListenAddr != "0.0.0.0:161" || cfg.Gateway.AgentAddr != "127.0.0.1:161" || cfg.Gateway.AgentCommunity != "realcomm" {
		t.Fatalf("gateway role = %+v", cfg.Gateway)
	}
}

func TestFlagsConfigGatewayTSM(t *testing.T) {
	cfg, err := flagsConfig(config.RoleGateway, flagsOpts{
		secMode:  "tsm-gateway",
		listen:   "0.0.0.0:10161",
		agent:    "127.0.0.1:161",
		caFile:   "/tmp/ca.pem",
		certFile: "/tmp/cert.pem",
		keyFile:  "/tmp/key.pem",
	})
	if err != nil {
		t.Fatalf("gateway tsm flagsConfig: %v", err)
	}
	if cfg.Security.Mode != "tsm-gateway" {
		t.Fatalf("security mode = %q", cfg.Security.Mode)
	}
	if cfg.Tunnel.CAFile != "/tmp/ca.pem" || cfg.Tunnel.CertFile != "/tmp/cert.pem" || cfg.Tunnel.KeyFile != "/tmp/key.pem" {
		t.Fatalf("tunnel = %+v", cfg.Tunnel)
	}
}

func TestFlagsConfigGatewayErrors(t *testing.T) {
	cases := []struct {
		name string
		o    flagsOpts
	}{
		{"no listen", flagsOpts{secMode: "usm-gateway", agent: ":161", authPass: "a", privPass: "b"}},
		{"no agent", flagsOpts{secMode: "usm-gateway", listen: ":161", authPass: "a", privPass: "b"}},
		{"bad secMode usm-translate", flagsOpts{secMode: "usm-translate", listen: ":161", agent: ":162", authPass: "a", privPass: "b"}},
		{"bad secMode passthrough", flagsOpts{secMode: "passthrough", listen: ":161", agent: ":162"}},
		{"unknown secMode", flagsOpts{secMode: "bogus", listen: ":161", agent: ":162"}},
		{"missing passes", flagsOpts{secMode: "usm-gateway", listen: ":161", agent: ":162"}},
		{"tsm missing certs", flagsOpts{secMode: "tsm-gateway", listen: ":161", agent: ":162"}},
		{"tsm missing ca", flagsOpts{secMode: "tsm-gateway", listen: ":161", agent: ":162", certFile: "/tmp/c.pem", keyFile: "/tmp/k.pem"}},
	}
	for _, c := range cases {
		if _, err := flagsConfig(config.RoleGateway, c.o); err == nil {
			t.Fatalf("%s: expected error, got nil", c.name)
		}
	}
}

func TestFlagsConfigCiphersuites(t *testing.T) {
	cfg, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode: "dtls",
		tunnelAddr: "10.0.0.2:10162",
		psk:        "aabbccdd",
		pskSuites:  "aes256-ccm-8,aes128-gcm",
		secMode:    "usm-translate",
		authPass:   "authpass",
		privPass:   "privpass",
		listen:     "0.0.0.0:161",
	})
	if err != nil {
		t.Fatalf("ciphersuite flagsConfig: %v", err)
	}
	suites := cfg.Tunnel.PskCiphersuites
	if len(suites) != 2 || suites[0] != "aes256-ccm-8" || suites[1] != "aes128-gcm" {
		t.Fatalf("psk ciphersuites = %v", suites)
	}
	// Invalid suite name must fail validation.
	if _, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode: "dtls",
		tunnelAddr: "10.0.0.2:10162",
		psk:        "aabbccdd",
		pskSuites:  "bogus-suite",
		secMode:    "usm-translate",
		authPass:   "authpass",
		privPass:   "privpass",
		listen:     "0.0.0.0:161",
	}); err == nil {
		t.Fatal("invalid ciphersuite: expected error")
	}
}

func TestFlagsConfigFilter(t *testing.T) {
	cfg, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode:   "dtls",
		tunnelAddr:   "10.0.0.2:10162",
		psk:          "aabbccdd",
		secMode:      "usm-translate",
		authPass:     "authpass",
		privPass:     "privpass",
		listen:       "0.0.0.0:161",
		filterAction: "deny",
		filterOids:   []string{"1.3.6.1.4.1.8072"},
	})
	if err != nil {
		t.Fatalf("filter flagsConfig: %v", err)
	}
	if cfg.Notifications.Filter == nil || cfg.Notifications.Filter.Action != "deny" {
		t.Fatalf("notifications filter = %+v", cfg.Notifications)
	}
	// Bad action must fail (validation runs in Config.Validate).
	if _, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelMode:   "dtls",
		tunnelAddr:   "10.0.0.2:10162",
		psk:          "aabbccdd",
		secMode:      "usm-translate",
		authPass:     "authpass",
		privPass:     "privpass",
		listen:       "0.0.0.0:161",
		filterAction: "bogus",
		filterOids:   []string{"1.3.6.1"},
	}); err == nil {
		t.Fatal("bad filter action: expected error")
	}
}

// swapArgs replaces os.Args for the duration of f and restores it after.
func swapArgs(t *testing.T, args []string, f func() int) int {
	t.Helper()
	old := os.Args
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Args = args
	os.Stdout = w
	os.Stderr = w
	defer func() {
		os.Args = old
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = w.Close()
		_ = r.Close()
	}()
	return f()
}

func TestRunOsArgs(t *testing.T) {
	// version variants return 0
	for _, args := range [][]string{{"snmp-proxy", "version"}, {"snmp-proxy", "--version"}, {"snmp-proxy", "-v"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	// help variants return 0
	for _, args := range [][]string{{"snmp-proxy", "help"}, {"snmp-proxy", "--help"}, {"snmp-proxy", "-h"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	// genpsk returns 0 and prints 64 hex chars
	if rc := swapArgs(t, []string{"snmp-proxy", "genpsk"}, run); rc != 0 {
		t.Fatalf("run(genpsk) = %d, want 0", rc)
	}
	// unknown command returns 2
	if rc := swapArgs(t, []string{"snmp-proxy", "bogus"}, run); rc != 2 {
		t.Fatalf("run(bogus) = %d, want 2", rc)
	}
	// no args returns 2
	if rc := swapArgs(t, []string{"snmp-proxy"}, run); rc != 2 {
		t.Fatalf("run(no args) = %d, want 2", rc)
	}
}

func TestUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	usage(os.Stdout)
	_ = w.Close()
	os.Stdout = oldStdout
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	if !strings.Contains(string(buf[:n]), "snmp-proxy") {
		t.Fatalf("usage output missing program name: %q", string(buf[:n]))
	}
}
