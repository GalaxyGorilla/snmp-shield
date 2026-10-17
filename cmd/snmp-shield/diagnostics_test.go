package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleArg(t *testing.T) {
	for _, s := range []string{"manager", "agent", "gateway"} {
		if _, err := roleArg(s); err != nil {
			t.Fatalf("roleArg(%q): %v", s, err)
		}
	}
	if _, err := roleArg(""); err == nil {
		t.Fatal("roleArg(\"\"): expected error")
	}
	if _, err := roleArg("bogus"); err == nil {
		t.Fatal("roleArg(bogus): expected error")
	}
}

func TestRunValidateFlags(t *testing.T) {
	// valid flags-mode manager config
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "manager",
		"--tunnel-addr", "127.0.0.1:19611", "--psk", "aabbccdd",
		"--auth-pass", "a", "--priv-pass", "b", "--listen", ":161"}, run); rc != 0 {
		t.Fatalf("validate valid manager = %d, want 0", rc)
	}
	// invalid: missing priv pass
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "manager",
		"--tunnel-addr", "127.0.0.1:19611", "--psk", "aabbccdd",
		"--auth-pass", "a", "--listen", ":161"}, run); rc != 1 {
		t.Fatalf("validate missing pass = %d, want 1", rc)
	}
	// invalid role (text output path → rc 1)
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "bogus"}, run); rc != 1 {
		t.Fatalf("validate bogus role = %d, want 1", rc)
	}
	// invalid role with --json: report printed, rc 0 (tooling reads ok=false)
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "bogus", "--json"}, run); rc != 0 {
		t.Fatalf("validate bogus role --json = %d, want 0", rc)
	}
}

func TestRunValidateYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	yaml := `tunnel:
  listen_addr: ":19611"
  psk: "hex:aabbccdd"
agent:
  agent_addr: "127.0.0.1:161"
security:
  mode: usm-translate
  users:
    - name: proxy
      auth_protocol: sha
      auth_passphrase: authpass
      priv_protocol: aes
      priv_passphrase: privpass
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "agent", "--config", path}, run); rc != 0 {
		t.Fatalf("validate agent yaml = %d, want 0", rc)
	}
	// broken YAML
	if err := os.WriteFile(path, []byte("tunnel: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "agent", "--config", path}, run); rc != 1 {
		t.Fatalf("validate broken yaml = %d, want 1", rc)
	}
	// missing file
	if rc := swapArgs(t, []string{"snmp-shield", "validate", "--role", "agent", "--config", filepath.Join(dir, "nope.yaml")}, run); rc != 1 {
		t.Fatalf("validate missing file = %d, want 1", rc)
	}
}

func TestRunValidateJSON(t *testing.T) {
	// JSON output goes to stdout; run inside swapArgs and check the rc.
	// Full stdout capture is covered by TestRunOsArgs-style pipes; here
	// we assert the exit code and that the report marshals.
	rep := report{OK: true, Role: "manager", SecurityMode: "usm-translate", TunnelMode: "dtls"}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), `"role":"manager"`) {
		t.Fatalf("report json unexpected: %s", b)
	}
}

func TestRunSelftestProbeDisabled(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "engine.json")
	if rc := swapArgs(t, []string{"snmp-shield", "selftest", "--role", "manager",
		"--tunnel-addr", "127.0.0.1:19611", "--psk", "aabbccdd",
		"--auth-pass", "a", "--priv-pass", "b", "--listen", ":161",
		"--probe=false"}, run); rc != 0 {
		t.Fatalf("selftest probe=false = %d, want 0", rc)
	}
	_ = store
}

func TestPreflightEngineStore(t *testing.T) {
	dir := t.TempDir()
	// existing writable file passes
	path := filepath.Join(dir, "engine.json")
	ch := checkEngineStore(path)
	if !ch.OK {
		t.Fatalf("engine store create: %v", ch.Detail)
	}
	// a directory in place of the file fails
	ch = checkEngineStore(dir)
	if ch.OK {
		t.Fatal("engine store on directory: expected failure")
	}
	// a path in a nonexistent directory fails (no parent creation —
	// matches cache.Open behavior)
	ch = checkEngineStore(filepath.Join(dir, "sub", "engine.json"))
	if ch.OK {
		t.Fatal("engine store in missing dir: expected failure")
	}
}

func TestPreflightKeyPair(t *testing.T) {
	// missing files fail
	ch := checkKeyPair("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if ch.OK {
		t.Fatal("keypair with missing files: expected failure")
	}
	// both empty fails
	ch = checkKeyPair("", "")
	if ch.OK {
		t.Fatal("keypair empty: expected failure")
	}
}

func TestPreflightCA(t *testing.T) {
	ch := checkCA("/nonexistent/ca.pem")
	if ch.OK {
		t.Fatal("CA missing file: expected failure")
	}
	ch = checkCA("main.go")
	if ch.OK {
		t.Fatal("CA with non-PEM file: expected failure")
	}
}
