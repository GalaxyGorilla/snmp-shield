// fuzz_test.go: fuzz target for the YAML config loader. Operators paste
// configs from wikis and vendor docs, and the loader is the first thing an
// appliance's web UI calls, so a malformed document must always produce an
// error — never a panic, never a half-validated Config.
//
//	go test ./internal/config -run '^$' -fuzz FuzzLoad -fuzztime 30s
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	seeds := []string{
		"",
		"role: manager\n",
		"role: gateway\nsecurity:\n  mode: usm-gateway\n",
		"access:\n  allow: [\"10.0.0.0/8\"]\n  read_only: true\n",
		"access:\n  write_policy:\n    default: deny\n    rules:\n      - oid: 1.3.6.1.4.1.99\n        action: allow\n",
		"tunnel:\n  dial_addrs: [\"127.0.0.1:1\"]\n  psk: nothex\n",
		"notifications:\n  filter:\n    action: deny\n    oids: [\"1.3.6.1.4.1.99\"]\n",
		"security:\n  users: [{name: a, auth_protocol: sha, auth_passphrase: x}]\n",
		"metrics:\n  base_oid: \"-1.-2\"\n",
		"\x00\x01\x02",
		"a: &a [*a]\n", // recursive alias: yaml.v3 must reject it
	}
	for _, s := range seeds {
		for _, role := range []string{"manager", "agent", "gateway"} {
			f.Add(s, role)
		}
	}

	dir := f.TempDir()
	path := filepath.Join(dir, "snmp-shield.yaml")

	// The role is a fuzz dimension (not a Go loop: F.Fuzz may only be
	// called once per target).
	f.Fuzz(func(t *testing.T, doc, roleName string) {
		role := Role(roleName)
		switch role {
		case RoleManager, RoleAgent, RoleGateway:
		default:
			role = RoleManager
		}
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path, role)
		if err != nil {
			return
		}
		// A config that loads must be fully usable: every compiled
		// sub-policy is built from validated input and cannot fail
		// afterwards, and it never panics.
		if _, aerr := cfg.AccessPolicy(); aerr != nil {
			t.Fatalf("Load accepted a config whose access policy does not compile: %v", aerr)
		}
		if _, ferr := cfg.TrapFilter(); ferr != nil {
			t.Fatalf("Load accepted a config whose notification filter does not compile: %v", ferr)
		}
		_ = cfg.DialEndpoints()
		_ = cfg.Keepalive()
		_ = cfg.Backoff()
		if _, perr := cfg.PSKBytes(); perr != nil && cfg.Tunnel.PSK != "" {
			t.Fatalf("Load accepted an unusable PSK %q: %v", cfg.Tunnel.PSK, perr)
		}
	})
}
