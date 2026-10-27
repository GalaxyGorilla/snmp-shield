package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManagerHexPSK(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
`)
	cfg, err := Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Role != RoleManager {
		t.Errorf("role = %q", cfg.Role)
	}
	if cfg.Tunnel.Mode != "dtls" || cfg.Tunnel.DialAddr != "10.0.0.1:10162" {
		t.Errorf("tunnel = %+v", cfg.Tunnel)
	}
	want := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	got, err := cfg.PSKBytes()
	if err != nil || string(got) != string(want) {
		t.Errorf("psk bytes = %x err=%v", got, err)
	}
	if cfg.Manager.ListenAddr != ":161" {
		t.Errorf("manager listen = %q", cfg.Manager.ListenAddr)
	}
	// Defaults applied.
	if cfg.Tunnel.KeepaliveSecs <= 0 {
		t.Errorf("keepalive default not applied: %d", cfg.Tunnel.KeepaliveSecs)
	}
	if cfg.Tunnel.MaxFrameSize <= 0 {
		t.Errorf("max_frame_size default not applied: %d", cfg.Tunnel.MaxFrameSize)
	}
}

func TestLoadAgentTextPSK(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: tls
  listen_addr: ":10162"
  psk: "text:shared-secret"
agent:
  agent_addr: "127.0.0.1:161"
`)
	cfg, err := Load(path, RoleAgent)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, err := cfg.PSKBytes()
	if err != nil || string(got) != "shared-secret" {
		t.Errorf("psk bytes = %q err=%v", got, err)
	}
	if cfg.Agent.AgentAddr != "127.0.0.1:161" {
		t.Errorf("agent addr = %q", cfg.Agent.AgentAddr)
	}
}

func TestPSKBareAndBadHex(t *testing.T) {
	c := &Config{Tunnel: Tunnel{PSK: "bare-secret"}}
	got, err := c.PSKBytes()
	if err != nil || string(got) != "bare-secret" {
		t.Errorf("bare psk = %q err=%v", got, err)
	}
	c = &Config{Tunnel: Tunnel{PSK: "hex:zzzz"}}
	if _, err := c.PSKBytes(); err == nil {
		t.Error("bad hex accepted")
	}
	empty := &Config{}
	if _, err := empty.PSKBytes(); err == nil {
		t.Error("empty psk accepted")
	}
}

func TestValidateErrors(t *testing.T) {
	goodM := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", DialAddr: "x:1", PSK: "text:s"}, Manager: ManagerRole{ListenAddr: ":161"}, Security: Security{Mode: "passthrough"}}
	if err := goodM.Validate(); err != nil {
		t.Errorf("manager validate: %v", err)
	}
	noDial := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", PSK: "text:s"}, Manager: ManagerRole{ListenAddr: ":161"}}
	if err := noDial.Validate(); err == nil {
		t.Error("manager without dial_addr accepted")
	}
	noListen := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", DialAddr: "x:1", PSK: "text:s"}}
	if err := noListen.Validate(); err == nil {
		t.Error("manager without listen_addr accepted")
	}
	goodA := &Config{Role: RoleAgent, Tunnel: Tunnel{Mode: "dtls", ListenAddr: ":10162", PSK: "text:s"}, Agent: AgentRole{AgentAddr: "127.0.0.1:161"}, Security: Security{Mode: "passthrough"}}
	if err := goodA.Validate(); err != nil {
		t.Errorf("agent validate: %v", err)
	}
	goodUSMNotifOnly := &Config{
		Role: RoleGateway,
		Gateway: GatewayRole{
			TrapListenAddr: ":162",
			TrapSinkAddr:   "127.0.0.1:10162",
		},
		Security: Security{
			Mode: "usm-gateway",
			Users: []UserCfg{{
				Name:           "proxy",
				AuthProtocol:   "sha",
				AuthPassphrase: "authpass",
				PrivProtocol:   "aes",
				PrivPassphrase: "privpass",
			}},
			// the notification-only shape still owns an authoritative
			// engine toward the manager
			EphemeralEngine: true,
		},
	}
	if err := goodUSMNotifOnly.Validate(); err != nil {
		t.Errorf("usm-gateway notification-only (trap legs only): %v", err)
	}
	halfNotify := &Config{
		Role:     RoleGateway,
		Gateway:  GatewayRole{TrapListenAddr: ":162"},
		Security: Security{Mode: "usm-gateway", Users: []UserCfg{{Name: "proxy", AuthProtocol: "sha", AuthPassphrase: "a", PrivProtocol: "aes", PrivPassphrase: "p"}}, EphemeralEngine: true},
	}
	if err := halfNotify.Validate(); err == nil {
		t.Error("usm-gateway with trap_listen but no trap_sink accepted")
	}
	noAgentAddr := &Config{Role: RoleAgent, Tunnel: Tunnel{Mode: "dtls", ListenAddr: ":10162", PSK: "text:s"}}
	if err := noAgentAddr.Validate(); err == nil {
		t.Error("agent without agent_addr accepted")
	}
	badMode := &Config{Role: RoleAgent, Tunnel: Tunnel{Mode: "quic", ListenAddr: ":10162", PSK: "text:s"}, Agent: AgentRole{AgentAddr: "x"}}
	if err := badMode.Validate(); err == nil {
		t.Error("bad tunnel mode accepted")
	}
	dtlsNoSecret := &Config{Role: RoleAgent, Tunnel: Tunnel{Mode: "dtls", ListenAddr: ":10162"}, Agent: AgentRole{AgentAddr: "x"}}
	if err := dtlsNoSecret.Validate(); err == nil {
		t.Error("dtls without psk/cert accepted")
	}
	badRole := &Config{Role: "router", Tunnel: Tunnel{Mode: "dtls", PSK: "text:s"}}
	if err := badRole.Validate(); err == nil {
		t.Error("bad role accepted")
	}
}

func TestLoadPskCiphersuites(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "text:shared-secret"
  psk_ciphersuites: ["aes256-ccm-8", "aes128-gcm"]
manager:
  listen_addr: ":161"
`)
	cfg, err := Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.Tunnel.PskCiphersuites
	if len(got) != 2 || got[0] != "aes256-ccm-8" || got[1] != "aes128-gcm" {
		t.Errorf("psk_ciphersuites = %v", got)
	}
}

func TestValidatePskCiphersuites(t *testing.T) {
	good := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", DialAddr: "x:1", PSK: "text:s", PskCiphersuites: []string{"aes256-ccm-8", "TLS_PSK_WITH_AES_128_CCM"}}, Manager: ManagerRole{ListenAddr: ":161"}, Security: Security{Mode: "passthrough"}}
	if err := good.Validate(); err != nil {
		t.Errorf("valid suites rejected: %v", err)
	}
	bad := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", DialAddr: "x:1", PSK: "text:s", PskCiphersuites: []string{"chacha20"}}, Manager: ManagerRole{ListenAddr: ":161"}, Security: Security{Mode: "passthrough"}}
	if err := bad.Validate(); err == nil {
		t.Error("unknown psk ciphersuite accepted")
	}
	// Suites without a PSK are also validated (harmless, forward-proof).
	noPSK := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "tls", DialAddr: "x:1", PskCiphersuites: []string{"bogus"}}, Manager: ManagerRole{ListenAddr: ":161"}, Security: Security{Mode: "passthrough"}}
	if err := noPSK.Validate(); err == nil {
		t.Error("unknown psk ciphersuite without psk accepted")
	}
	// No suites configured: valid everywhere.
	none := &Config{Role: RoleAgent, Tunnel: Tunnel{Mode: "tls", ListenAddr: ":10162"}, Agent: AgentRole{AgentAddr: "127.0.0.1:161"}, Security: Security{Mode: "passthrough"}}
	if err := none.Validate(); err != nil {
		t.Errorf("no suites rejected: %v", err)
	}
}

func TestKeepaliveAndBackoff(t *testing.T) {
	c := &Config{Tunnel: Tunnel{KeepaliveSecs: 7, MaxReconnectBackoff: 3}}
	if got := c.Keepalive(); got != 7*time.Second {
		t.Errorf("keepalive = %v", got)
	}
	if got := c.Backoff(); got != 3*time.Second {
		t.Errorf("backoff = %v", got)
	}
	zero := &Config{}
	zero.Defaults()
	if zero.Keepalive() <= 0 || zero.Backoff() <= 0 {
		t.Error("zero config must yield positive defaults")
	}
}

func TestDialAddrs(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: dtls
  dial_addrs:
    - "10.0.0.1:10162"
    - "10.0.0.2:10162"
  psk: "text:shared-secret"
manager:
  listen_addr: ":161"
`)
	cfg, err := Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	addrs := cfg.DialEndpoints()
	if len(addrs) != 2 || addrs[0] != "10.0.0.1:10162" || addrs[1] != "10.0.0.2:10162" {
		t.Errorf("dial_addrs = %v", addrs)
	}

	// dial_addrs wins over dial_addr.
	path = writeTemp(t, `
tunnel:
  mode: dtls
  dial_addr: "10.0.0.9:10162"
  dial_addrs: ["10.0.0.1:10162"]
  psk: "text:shared-secret"
manager:
  listen_addr: ":161"
`)
	cfg, err = Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load dial_addrs+dial_addr: %v", err)
	}
	if addrs := cfg.DialEndpoints(); len(addrs) != 1 || addrs[0] != "10.0.0.1:10162" {
		t.Errorf("dial_addrs must win over dial_addr: %v", addrs)
	}

	// Legacy single dial_addr still resolves.
	legacy := &Config{Tunnel: Tunnel{DialAddr: "x:1"}}
	if addrs := legacy.DialEndpoints(); len(addrs) != 1 || addrs[0] != "x:1" {
		t.Errorf("legacy dial_addr = %v", addrs)
	}

	// Manager without either is rejected.
	none := &Config{Role: RoleManager, Tunnel: Tunnel{Mode: "dtls", PSK: "text:s"}, Manager: ManagerRole{ListenAddr: ":161"}}
	if err := none.Validate(); err == nil {
		t.Error("manager without dial_addr/dial_addrs accepted")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml", RoleManager); err == nil {
		t.Error("missing file accepted")
	}
}

func TestLoadBadYAML(t *testing.T) {
	path := writeTemp(t, "tunnel: [unclosed")
	if _, err := Load(path, RoleManager); err == nil {
		t.Error("bad yaml accepted")
	}
}

func TestTrapFilterFromConfig(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
notifications:
  filter:
    action: deny
    oids:
      - "1.3.6.1.6.3.1.1.5.2"
      - "1.3.6.1.4.1.8072"
`)
	cfg, err := Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	filt, err := cfg.TrapFilter()
	if err != nil {
		t.Fatalf("TrapFilter: %v", err)
	}
	if filt == nil {
		t.Fatal("TrapFilter returned nil for configured filter")
	}
	if filt.Allowed("1.3.6.1.6.3.1.1.5.2") {
		t.Error("deny filter must not allow configured OID")
	}
	if filt.Allowed("1.3.6.1.4.1.8072.999") {
		t.Error("deny filter must not allow child of configured OID")
	}
	if !filt.Allowed("1.3.6.1.6.3.1.1.5.1") {
		t.Error("deny filter must allow non-matching OID")
	}
}

func TestTrapFilterNilWhenUnset(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
`)
	cfg, err := Load(path, RoleManager)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	filt, err := cfg.TrapFilter()
	if err != nil {
		t.Fatalf("TrapFilter: %v", err)
	}
	if filt != nil {
		t.Error("TrapFilter must be nil when no filter is configured")
	}
}

func TestTrapFilterInvalidConfig(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			"bad action",
			`
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
notifications:
  filter:
    action: drop
    oids: ["1.3.6.1"]
`,
			true,
		},
		{
			"empty oids",
			`
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
notifications:
  filter:
    action: allow
    oids: []
`,
			true,
		},
		{
			"invalid oid",
			`
tunnel:
  mode: dtls
  dial_addr: "10.0.0.1:10162"
  psk: "hex:00112233445566778899aabbccddeeff"
manager:
  listen_addr: ":161"
notifications:
  filter:
    action: allow
    oids: ["not-an-oid"]
`,
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.yaml)
			_, err := Load(path, RoleManager)
			if tc.wantErr && err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("%s: unexpected error: %v", tc.name, err)
			}
		})
	}
}

func TestTrapFilterValidatesForGatewayRole(t *testing.T) {
	// The filter validation runs before the gateway branch returns early.
	path := writeTemp(t, `
gateway:
  listen_addr: ":161"
  agent_addr: "127.0.0.1:161"
security:
  mode: usm-gateway
  users:
    - name: proxy
      auth_protocol: sha
      auth_passphrase: authpass
      priv_protocol: aes
      priv_passphrase: privpass
notifications:
  filter:
    action: bogus
    oids: ["1.3.6.1"]
`)
	if _, err := Load(path, RoleGateway); err == nil {
		t.Error("invalid filter action must be rejected for gateway role")
	}
}

// --- security.user validation ---------------------------------------------

// gwCfg builds a minimal valid usm-gateway config (request path) whose
// users/engine-store can be overridden per test.
func gwCfg(users []UserCfg, store string, ephemeral bool) *Config {
	return &Config{
		Role:    RoleGateway,
		Gateway: GatewayRole{ListenAddr: ":161", AgentAddr: "127.0.0.1:161"},
		Security: Security{
			Mode:            "usm-gateway",
			Users:           users,
			EngineStore:     store,
			EphemeralEngine: ephemeral,
		},
	}
}

func goodUser() UserCfg {
	return UserCfg{
		Name:           "proxy",
		AuthProtocol:   "sha",
		AuthPassphrase: "authpass",
		PrivProtocol:   "aes",
		PrivPassphrase: "privpass",
	}
}

func TestValidateUserProtocolNames(t *testing.T) {
	// a typo used to silently delete the user at runtime: every request
	// from that manager then failed with usmStatsUnknownUserNames
	u := goodUser()
	u.AuthProtocol = "shaa"
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("unknown auth_protocol accepted")
	}
	u = goodUser()
	u.PrivProtocol = "aes99"
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("unknown priv_protocol accepted")
	}
	// aliases stay legal
	u = goodUser()
	u.AuthProtocol = "sha256"
	u.PrivProtocol = "aes256"
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err != nil {
		t.Errorf("sha256/aes256 rejected: %v", err)
	}
}

func TestValidateUserPassphrases(t *testing.T) {
	u := goodUser()
	u.AuthPassphrase = ""
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("auth user without auth_passphrase accepted")
	}
	u = goodUser()
	u.PrivPassphrase = ""
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("priv user without priv_passphrase accepted")
	}
	// privacy without authentication is meaningless
	u = goodUser()
	u.AuthProtocol = "none"
	u.AuthPassphrase = ""
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("priv_protocol with auth_protocol none accepted")
	}
	dup := goodUser()
	if err := gwCfg([]UserCfg{goodUser(), dup}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("duplicate user names accepted")
	}
}

func TestValidateRejectsNoAuthUsers(t *testing.T) {
	// the gateway is a security gate: it must never relay on behalf of an
	// unauthenticated (noAuthNoPriv) identity
	u := goodUser()
	u.AuthProtocol = "none"
	u.AuthPassphrase = ""
	u.PrivProtocol = "none"
	u.PrivPassphrase = ""
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err == nil {
		t.Error("noAuthNoPriv user accepted in usm-gateway mode")
	}
	// authNoPriv stays legal
	u = goodUser()
	u.PrivProtocol = "none"
	u.PrivPassphrase = ""
	if err := gwCfg([]UserCfg{u}, "/tmp/e.json", false).Validate(); err != nil {
		t.Errorf("authNoPriv user rejected: %v", err)
	}
}

func TestValidateEngineStoreRequired(t *testing.T) {
	// authoritative-engine modes must persist engineBoots
	if err := gwCfg([]UserCfg{goodUser()}, "", false).Validate(); err == nil {
		t.Error("usm-gateway without engine_store accepted")
	}
	if err := gwCfg([]UserCfg{goodUser()}, "", true).Validate(); err != nil {
		t.Errorf("explicit ephemeral engine rejected: %v", err)
	}
	if err := gwCfg([]UserCfg{goodUser()}, "/var/lib/snmp-shield/e.json", false).Validate(); err != nil {
		t.Errorf("persistent engine store rejected: %v", err)
	}
	// the manager-gateway FOLLOWS the agent's engine: no store needed
	mgw := &Config{
		Role:     RoleGateway,
		Gateway:  GatewayRole{ListenAddr: ":161", AgentAddr: "10.0.0.9:161"},
		Security: Security{Mode: "usm-manager-gateway", Users: []UserCfg{goodUser()}},
	}
	if err := mgw.Validate(); err != nil {
		t.Errorf("usm-manager-gateway requires no engine store: %v", err)
	}
	// two-proxy usm-translate terminates USM on both sides: required too
	tr := &Config{
		Role:     RoleAgent,
		Tunnel:   Tunnel{Mode: "dtls", ListenAddr: ":10162", PSK: "text:s"},
		Agent:    AgentRole{AgentAddr: "127.0.0.1:161"},
		Security: Security{Mode: "usm-translate", Users: []UserCfg{goodUser()}},
	}
	if err := tr.Validate(); err == nil {
		t.Error("usm-translate without engine_store accepted")
	}
	tr.Security.EphemeralEngine = true
	if err := tr.Validate(); err != nil {
		t.Errorf("usm-translate with explicit ephemeral engine rejected: %v", err)
	}
}

// --- access policy ---------------------------------------------------------

// gwAccess builds a minimal valid usm-gateway config with an access section.
func gwAccess(a Access) *Config {
	c := gwCfg([]UserCfg{goodUser()}, "/tmp/e.json", false)
	c.Access = a
	return c
}

func TestValidateAccess(t *testing.T) {
	// client allow-list entries must be IPs or CIDR ranges
	if err := gwAccess(Access{Allow: []string{"10.0.0.0/33"}}).Validate(); err == nil {
		t.Error("invalid CIDR in access.allow accepted")
	}
	if err := gwAccess(Access{Allow: []string{"not-an-ip"}}).Validate(); err == nil {
		t.Error("invalid IP in access.allow accepted")
	}
	if err := gwAccess(Access{Allow: []string{"10.0.0.5", "10.8.0.0/24", "2001:db8::/32"}}).Validate(); err != nil {
		t.Errorf("valid access.allow rejected: %v", err)
	}
	if err := gwAccess(Access{RatePerSec: -1}).Validate(); err == nil {
		t.Error("negative access.rate_per_sec accepted")
	}
	// read_only and write_policy are two ways to say the same thing
	both := Access{ReadOnly: true, WritePolicy: &WritePolicyCfg{
		Default: "allow",
	}}
	if err := gwAccess(both).Validate(); err == nil {
		t.Error("read_only + write_policy accepted")
	}
}

func TestValidateWritePolicy(t *testing.T) {
	bad := []WritePolicyCfg{
		{Default: "maybe"},
		{Rules: []WriteRuleCfg{{OID: "", Action: "allow"}}},
		{Rules: []WriteRuleCfg{{OID: "not-an-oid", Action: "allow"}}},
		{Rules: []WriteRuleCfg{{OID: "1.3.6.1", Action: "drop"}}},
		// no rules + default deny is what read_only is for
		{Default: "deny"},
		{},
	}
	for i, wp := range bad {
		if err := gwAccess(Access{WritePolicy: &wp}).Validate(); err == nil {
			t.Errorf("write_policy case %d accepted: %+v", i, wp)
		}
	}
	good := []WritePolicyCfg{
		{Default: "allow"},
		{Default: "deny", Rules: []WriteRuleCfg{{OID: "1.3.6.1.4.1.99.1", Action: "allow"}}},
		{Rules: []WriteRuleCfg{{OID: ".1.3.6.1.4.1.99", Action: "deny"}, {OID: "1.3.6.1.2", Action: "allow"}}},
	}
	for i, wp := range good {
		if err := gwAccess(Access{WritePolicy: &wp}).Validate(); err != nil {
			t.Errorf("valid write_policy case %d rejected: %v", i, err)
		}
	}
}

func TestAccessPolicyCompiles(t *testing.T) {
	// zero value: nil policy (allow everything)
	p, err := (&Config{}).AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Error("empty access section produced a policy")
	}

	c := gwAccess(Access{
		Allow:      []string{"10.8.0.0/24"},
		RatePerSec: 25,
		WritePolicy: &WritePolicyCfg{
			Default: "deny",
			Rules:   []WriteRuleCfg{{OID: "1.3.6.1.4.1.99.1", Action: "allow"}},
		},
	})
	p, err = c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("access section produced a nil policy")
	}
	if p.ReadOnly() {
		t.Error("write_policy reported as read_only")
	}
	if p.WritePolicyRules() != 1 {
		t.Errorf("WritePolicyRules() = %d, want 1", p.WritePolicyRules())
	}

	ro, err := gwAccess(Access{ReadOnly: true}).AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !ro.ReadOnly() {
		t.Error("read_only did not compile to a read-only policy")
	}
}

func TestLoadAccessYAML(t *testing.T) {
	path := writeTemp(t, `
tunnel:
  listen_addr: ":19611"
  psk: "hex:aabbccdd"
agent:
  agent_addr: "127.0.0.1:161"
security:
  mode: passthrough
access:
  allow: ["10.8.0.0/24", "192.168.1.5"]
  rate_per_sec: 50
  write_policy:
    default: deny
    rules:
      - oid: "1.3.6.1.4.1.99.1"
        action: allow
      - oid: "1.3.6.1.4.1.99.1.9"
        action: deny
`)
	cfg, err := Load(path, RoleAgent)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Access.Allow) != 2 || cfg.Access.RatePerSec != 50 {
		t.Fatalf("access = %+v", cfg.Access)
	}
	if cfg.Access.WritePolicy == nil || len(cfg.Access.WritePolicy.Rules) != 2 {
		t.Fatalf("write_policy = %+v", cfg.Access.WritePolicy)
	}
	if _, err := cfg.AccessPolicy(); err != nil {
		t.Errorf("compiled policy: %v", err)
	}
}
