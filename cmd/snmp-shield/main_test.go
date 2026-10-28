// cmd smoke test: verify the flag-built configs validate and load for both
// roles, and that flag-vs-YAML equivalence holds (package main).
package main

import (
	"os"
	"strings"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
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

func TestFlagsConfigGatewayUSMNotifOnly(t *testing.T) {
	cfg, err := flagsConfig(config.RoleGateway, flagsOpts{
		secMode:    "usm-gateway",
		authPass:   "authpass",
		privPass:   "privpass",
		trapListen: ":162",
		trapSink:   "127.0.0.1:10162",
	})
	if err != nil {
		t.Fatalf("gateway usm-gateway notification-only flagsConfig: %v", err)
	}
	if cfg.Security.Mode != "usm-gateway" {
		t.Fatalf("security mode = %q", cfg.Security.Mode)
	}
	if cfg.Gateway.ListenAddr != "" || cfg.Gateway.AgentAddr != "" {
		t.Fatalf("notification-only usm-gateway unexpectedly configured request leg: %+v", cfg.Gateway)
	}
	if cfg.Gateway.TrapListenAddr != ":162" || cfg.Gateway.TrapSinkAddr != "127.0.0.1:10162" {
		t.Fatalf("gateway trap legs = %+v", cfg.Gateway)
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

// TestFlagsConfigGatewayAccessPolicy is a regression pin: the gateway role
// returned early from flagsConfig and silently dropped the access-policy
// flags, so `--read-only` (and --allow/--rate-per-sec/--write-*) built a
// policy and then threw it away for exactly the modes that face third-party
// clients. Caught by the vendor conformance matrix, not by unit tests.
func TestFlagsConfigGatewayAccessPolicy(t *testing.T) {
	cases := []struct {
		name string
		opts flagsOpts
	}{
		{
			name: "usm-gateway",
			opts: flagsOpts{secMode: "usm-gateway", listen: ":161", agent: "127.0.0.1:161",
				authPass: "a", privPass: "b", readOnly: true, allow: []string{"10.0.0.0/8"}},
		},
		{
			name: "usm-gateway-notif-only",
			opts: flagsOpts{secMode: "usm-gateway", trapListen: ":162", trapSink: "127.0.0.1:1162",
				authPass: "a", privPass: "b", readOnly: true},
		},
		{
			name: "usm-manager-gateway",
			opts: flagsOpts{secMode: "usm-manager-gateway", listen: ":161", agent: "127.0.0.1:161",
				authPass: "a", privPass: "b", writeDefault: "deny",
				writeAllow: []string{"1.3.6.1.4.1.99"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := flagsConfig(config.RoleGateway, tc.opts)
			if err != nil {
				t.Fatalf("flagsConfig: %v", err)
			}
			if tc.opts.readOnly {
				if !cfg.Access.ReadOnly {
					t.Fatalf("--read-only was dropped: access = %+v", cfg.Access)
				}
				pol, perr := cfg.AccessPolicy()
				if perr != nil {
					t.Fatalf("compiling the policy: %v", perr)
				}
				if pol == nil {
					t.Fatal("no policy compiled from --read-only")
				}
			}
			if len(tc.opts.allow) > 0 && len(cfg.Access.Allow) != len(tc.opts.allow) {
				t.Fatalf("--allow was dropped: access = %+v", cfg.Access)
			}
			if tc.opts.writeDefault != "" {
				if cfg.Access.WritePolicy == nil {
					t.Fatalf("--write-default was dropped: access = %+v", cfg.Access)
				}
				if got := cfg.Access.WritePolicy.Default; got != tc.opts.writeDefault {
					t.Fatalf("write default = %q, want %q", got, tc.opts.writeDefault)
				}
			}
		})
	}
}

func TestFlagsConfigGatewayErrors(t *testing.T) {
	cases := []struct {
		name string
		o    flagsOpts
	}{
		{"listen without agent", flagsOpts{secMode: "usm-gateway", listen: ":161", authPass: "a", privPass: "b"}},
		{"agent without listen", flagsOpts{secMode: "usm-gateway", agent: ":161", authPass: "a", privPass: "b"}},
		{"trap-listen without trap-sink", flagsOpts{secMode: "usm-gateway", trapListen: ":162", authPass: "a", privPass: "b"}},
		{"trap-sink without trap-listen", flagsOpts{secMode: "usm-gateway", trapSink: ":10162", authPass: "a", privPass: "b"}},
		{"no legs at all", flagsOpts{secMode: "usm-gateway", authPass: "a", privPass: "b"}},
		{"bad secMode usm-translate", flagsOpts{secMode: "usm-translate", listen: ":161", agent: ":162", authPass: "a", privPass: "b"}},
		{"bad secMode passthrough", flagsOpts{secMode: "passthrough", listen: ":161", agent: ":162"}},
		{"removed secMode usm-manager", flagsOpts{secMode: "usm-manager", trapListen: ":162", trapSink: ":10162", authPass: "a", privPass: "b"}},
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
	for _, args := range [][]string{{"snmp-shield", "version"}, {"snmp-shield", "--version"}, {"snmp-shield", "-v"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	// help variants return 0
	for _, args := range [][]string{{"snmp-shield", "help"}, {"snmp-shield", "--help"}, {"snmp-shield", "-h"}} {
		if rc := swapArgs(t, args, run); rc != 0 {
			t.Fatalf("run(%v) = %d, want 0", args, rc)
		}
	}
	// genpsk returns 0 and prints 64 hex chars
	if rc := swapArgs(t, []string{"snmp-shield", "genpsk"}, run); rc != 0 {
		t.Fatalf("run(genpsk) = %d, want 0", rc)
	}
	// unknown command returns 2
	if rc := swapArgs(t, []string{"snmp-shield", "bogus"}, run); rc != 2 {
		t.Fatalf("run(bogus) = %d, want 2", rc)
	}
	// no args returns 2
	if rc := swapArgs(t, []string{"snmp-shield"}, run); rc != 2 {
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
	if !strings.Contains(string(buf[:n]), "snmp-shield") {
		t.Fatalf("usage output missing program name: %q", string(buf[:n]))
	}
}

// --- access policy flags ---------------------------------------------------

func TestAccessPolicyFlags(t *testing.T) {
	// no access flags: no section at all
	a, err := accessPolicy(flagsOpts{})
	if err != nil || a != nil {
		t.Fatalf("accessPolicy(none) = %+v, %v; want nil, nil", a, err)
	}

	// allow-list + rate only
	a, err = accessPolicy(flagsOpts{allow: []string{"10.8.0.0/24"}, ratePerSec: 40})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || len(a.Allow) != 1 || a.RatePerSec != 40 || a.WritePolicy != nil || a.ReadOnly {
		t.Fatalf("accessPolicy(allow+rate) = %+v", a)
	}

	// read-only
	a, err = accessPolicy(flagsOpts{readOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || !a.ReadOnly {
		t.Fatalf("accessPolicy(read-only) = %+v", a)
	}

	// read-only and write subtrees cannot be combined
	if _, err := accessPolicy(flagsOpts{readOnly: true, writeAllow: []string{"1.3.6.1"}}); err == nil {
		t.Error("--read-only with --write-allow accepted")
	}

	// explicit write policy: deny by default, one allowed and one denied
	// subtree (deny appended last; evaluation is order-independent)
	a, err = accessPolicy(flagsOpts{
		writeAllow: []string{"1.3.6.1.4.1.99.1"},
		writeDeny:  []string{"1.3.6.1.4.1.99.1.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || a.WritePolicy == nil {
		t.Fatal("write policy not built")
	}
	if a.WritePolicy.Default != "deny" {
		t.Errorf("default = %q, want deny", a.WritePolicy.Default)
	}
	if len(a.WritePolicy.Rules) != 2 ||
		a.WritePolicy.Rules[0].Action != "allow" || a.WritePolicy.Rules[1].Action != "deny" {
		t.Errorf("rules = %+v", a.WritePolicy.Rules)
	}
	// --write-default alone enables the policy
	a, err = accessPolicy(flagsOpts{writeDefault: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || a.WritePolicy == nil || a.WritePolicy.Default != "allow" {
		t.Fatalf("accessPolicy(write-default allow) = %+v", a)
	}
}

func TestFlagsConfigAccess(t *testing.T) {
	cfg, err := flagsConfig(config.RoleManager, flagsOpts{
		tunnelAddr: "127.0.0.1:19611",
		psk:        "00112233445566778899aabbccddeeff",
		secMode:    "passthrough",
		authPass:   "authpass",
		privPass:   "privpass",
		listen:     "127.0.0.1:161",
		allow:      []string{"127.0.0.1"},
		readOnly:   true,
	})
	if err != nil {
		t.Fatalf("flagsConfig with access: %v", err)
	}
	if len(cfg.Access.Allow) != 1 || !cfg.Access.ReadOnly {
		t.Fatalf("access = %+v", cfg.Access)
	}
	pol, err := cfg.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil || !pol.ReadOnly() {
		t.Fatalf("compiled access policy = %v", pol)
	}
}
