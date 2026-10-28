// Flags-mode wiring sweep: every role × security mode is exercised with the
// FULL flag set, and every config-bound flag is asserted to survive assembly.
//
// The reason this exists as a sweep rather than as one more happy-path test:
// conformance finding 1 was a flag silently dropped on a single code path
// (`flagsConfig` returned early for the gateway role, so `--read-only` and
// friends never reached the config). A per-feature test written against the
// path that works cannot catch that class; a table over every path can. The
// sweep also fails when a new field is added to flagsOpts but not to
// fullOpts below, so the table cannot rot into a list of the flags that
// happened to exist when it was written.
package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/spf13/pflag"
)

// fullOpts sets every flagsOpts field to a non-default value. The sweep
// mutates copies of it per case; TestOptsWiresEveryFlag additionally
// requires no field to stay zero, which is what keeps this complete as the
// flag set grows.
func fullOpts() flagsOpts {
	return flagsOpts{
		tunnelMode:   "tls",
		tunnelAddr:   "10.1.2.3:1161",
		psk:          "aabbccdd",
		pskIdentity:  "sweep-identity",
		pskSuites:    "aes256-ccm-8,aes128-gcm",
		insecure:     true,
		maxSessions:  17,
		secMode:      "usm-translate",
		authPass:     "auth-passphrase",
		privPass:     "priv-passphrase",
		engineStore:  "/var/lib/snmp-shield/engine.json",
		engineID:     "8000000001020304",
		v3User:       "agent-user",
		caFile:       "/etc/snmp-shield/ca.pem",
		certFile:     "/etc/snmp-shield/cert.pem",
		keyFile:      "/etc/snmp-shield/key.pem",
		listen:       "10.9.8.7:161",
		agent:        "10.9.8.6:161",
		community:    "sweep-comm",
		trapListen:   "10.9.8.7:162",
		trapSink:     "10.9.8.5:162",
		filterAction: "deny",
		filterOids:   []string{"1.3.6.1.4.1.8072", "1.3.6.1.6.3.1.1.5"},
		allow:        []string{"10.0.0.0/8", "192.0.2.7"},
		ratePerSec:   23,
		// readOnly is a sweep dimension: accessVariants() sets both
		// shapes explicitly. Non-zero here satisfies the completeness
		// tripwire and is what --read-only maps to.
		readOnly:     true,
		writeDefault: "allow",
		writeAllow:   []string{"1.3.6.1.4.1.99"},
		writeDeny:    []string{"1.3.6.1.4.1.99.1"},
		snmpListen:   "10.9.8.7:1161",
		snmpComm:     "sweep-metrics",
		snmpBaseOID:  "1.3.6.1.4.1.424242",
		snmpTrapSink: "10.9.8.5:1162",
	}
}

// wiringCheck is one wiring group; a case lists the groups that apply to it.
type wiringCheck func(t *testing.T, o flagsOpts, cfg *config.Config)

// sweepCase is one (role, security mode) path through flagsConfig.
type sweepCase struct {
	name   string
	role   config.Role
	mode   string
	adjust func(*flagsOpts) // required per-case values (list vs single addr, cleared legs, ...)
	checks []wiringCheck
}

func TestFlagsWiringSweep(t *testing.T) {
	cases := []sweepCase{
		{
			name: "manager/usm-translate", role: config.RoleManager, mode: "usm-translate",
			adjust: func(o *flagsOpts) {
				// The manager dials a comma-separated HA list.
				o.tunnelAddr = "10.1.2.3:1161, 10.1.2.4:1161"
			},
			checks: []wiringCheck{checkTunnel, checkMaxSessions, checkUSMUser, checkManagerLegs,
				checkTrapLegs, checkFilter, checkMetrics, checkEngine},
		},
		{
			name: "manager/passthrough", role: config.RoleManager, mode: "passthrough",
			adjust: func(o *flagsOpts) { o.tunnelAddr = "10.1.2.3:1161" },
			checks: []wiringCheck{checkTunnel, checkMaxSessions, checkManagerLegs,
				checkTrapLegs, checkFilter, checkMetrics, checkEngine},
		},
		{
			name: "agent/usm-translate", role: config.RoleAgent, mode: "usm-translate",
			adjust: func(o *flagsOpts) { o.tunnelAddr = "10.1.2.3:1161" },
			checks: []wiringCheck{checkTunnel, checkMaxSessions, checkUSMUser, checkAgentLegs,
				checkTrapLegs, checkFilter, checkMetrics, checkEngine},
		},
		{
			name: "agent/passthrough", role: config.RoleAgent, mode: "passthrough",
			adjust: func(o *flagsOpts) { o.tunnelAddr = "10.1.2.3:1161" },
			checks: []wiringCheck{checkTunnel, checkMaxSessions, checkAgentLegs,
				checkTrapLegs, checkFilter, checkMetrics, checkEngine},
		},
		{
			name: "gateway/usm-gateway", role: config.RoleGateway, mode: "usm-gateway",
			checks: []wiringCheck{checkUSMUser, checkGatewayLegs, checkTrapLegs, checkFilter,
				checkMetrics, checkEngine},
		},
		{
			name: "gateway/usm-gateway-notif-only", role: config.RoleGateway, mode: "usm-gateway",
			adjust: func(o *flagsOpts) { o.listen, o.agent = "", "" },
			checks: []wiringCheck{checkUSMUser, checkGatewayLegs, checkTrapLegs, checkFilter,
				checkMetrics, checkEngine},
		},
		{
			name: "gateway/usm-manager-gateway", role: config.RoleGateway, mode: "usm-manager-gateway",
			checks: []wiringCheck{checkUSMUser, checkGatewayLegs, checkTrapLegs, checkFilter,
				checkMetrics, checkEngine},
		},
		{
			name: "gateway/tsm-gateway", role: config.RoleGateway, mode: "tsm-gateway",
			checks: []wiringCheck{checkCertMaterial, checkMaxSessions, checkGatewayLegs,
				checkTrapLegs, checkFilter, checkMetrics, checkEngine},
		},
	}

	for _, tc := range cases {
		for _, av := range accessVariants() {
			t.Run(tc.name+"/"+av.name, func(t *testing.T) {
				o := fullOpts()
				o.secMode = tc.mode
				if tc.adjust != nil {
					tc.adjust(&o)
				}
				av.apply(&o)

				cfg, err := flagsConfig(tc.role, o)
				if err != nil {
					t.Fatalf("flagsConfig: %v", err)
				}
				if cfg.Security.Mode != tc.mode {
					t.Fatalf("security mode = %q, want %q", cfg.Security.Mode, tc.mode)
				}
				for _, c := range tc.checks {
					c(t, o, cfg)
				}
				av.verify(t, cfg)
			})
		}
	}
}

// --- wiring groups -------------------------------------------------------

func checkTunnel(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Tunnel.Mode != o.tunnelMode {
		t.Errorf("tunnel mode = %q, want %q", cfg.Tunnel.Mode, o.tunnelMode)
	}
	if cfg.Tunnel.PSK != "hex:"+o.psk {
		t.Errorf("psk = %q, want hex:<flag>", cfg.Tunnel.PSK)
	}
	if cfg.Tunnel.PSKIdentity != o.pskIdentity {
		t.Errorf("psk identity = %q, want %q", cfg.Tunnel.PSKIdentity, o.pskIdentity)
	}
	if want := []string{"aes256-ccm-8", "aes128-gcm"}; !reflect.DeepEqual(cfg.Tunnel.PskCiphersuites, want) {
		t.Errorf("ciphersuites = %v, want %v", cfg.Tunnel.PskCiphersuites, want)
	}
	if !cfg.Tunnel.InsecureSkipVerify {
		t.Error("--insecure was dropped")
	}
	if cfg.Security.EphemeralEngine {
		t.Error("--engine-store was dropped (engine still marked ephemeral)")
	}
}

func checkMaxSessions(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Tunnel.MaxSessions != o.maxSessions {
		t.Errorf("max sessions = %d, want %d", cfg.Tunnel.MaxSessions, o.maxSessions)
	}
}

func checkUSMUser(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if len(cfg.Security.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(cfg.Security.Users))
	}
	u := cfg.Security.Users[0]
	wantName := o.v3User
	if cfg.Security.Mode != "usm-manager-gateway" {
		wantName = "proxy"
	}
	if u.Name != wantName {
		t.Errorf("user name = %q, want %q", u.Name, wantName)
	}
	if u.AuthProtocol != "sha" || u.PrivProtocol != "aes" {
		t.Errorf("protocols = %s/%s, want sha/aes", u.AuthProtocol, u.PrivProtocol)
	}
	if u.AuthPassphrase != o.authPass || u.PrivPassphrase != o.privPass {
		t.Error("--auth-pass/--priv-pass were dropped")
	}
	// The community belongs to the user profile only where the mode
	// translates toward a clear agent; the gateways carry it on the
	// gateway leg instead (checked in checkGatewayLegs).
	if cfg.Role != config.RoleGateway && u.Community != o.community {
		t.Errorf("user community = %q, want %q", u.Community, o.community)
	}
}

func checkCertMaterial(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Tunnel.CAFile != o.caFile || cfg.Tunnel.CertFile != o.certFile || cfg.Tunnel.KeyFile != o.keyFile {
		t.Errorf("cert material = %q/%q/%q, want %q/%q/%q",
			cfg.Tunnel.CAFile, cfg.Tunnel.CertFile, cfg.Tunnel.KeyFile,
			o.caFile, o.certFile, o.keyFile)
	}
}

func checkManagerLegs(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Manager.ListenAddr != o.listen {
		t.Errorf("manager listen = %q, want %q", cfg.Manager.ListenAddr, o.listen)
	}
	want := splitList(o.tunnelAddr)
	if !reflect.DeepEqual(cfg.Tunnel.DialAddrs, want) {
		t.Errorf("dial addrs = %v, want %v", cfg.Tunnel.DialAddrs, want)
	}
}

func checkAgentLegs(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Agent.AgentAddr != o.agent {
		t.Errorf("agent addr = %q, want %q", cfg.Agent.AgentAddr, o.agent)
	}
	if cfg.Tunnel.ListenAddr != o.tunnelAddr {
		t.Errorf("tunnel listen = %q, want %q", cfg.Tunnel.ListenAddr, o.tunnelAddr)
	}
}

func checkGatewayLegs(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	g := cfg.Gateway
	if g.ListenAddr != o.listen || g.AgentAddr != o.agent {
		t.Errorf("request leg = %q -> %q, want %q -> %q", g.ListenAddr, g.AgentAddr, o.listen, o.agent)
	}
	if g.AgentCommunity != o.community {
		t.Errorf("agent community = %q, want %q", g.AgentCommunity, o.community)
	}
}

func checkTrapLegs(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	var gotListen, gotSink string
	switch cfg.Role {
	case config.RoleGateway:
		gotListen, gotSink = cfg.Gateway.TrapListenAddr, cfg.Gateway.TrapSinkAddr
	case config.RoleManager:
		gotListen, gotSink = cfg.Manager.TrapListenAddr, cfg.Manager.TrapSinkAddr
	case config.RoleAgent:
		gotListen, gotSink = cfg.Agent.TrapListenAddr, cfg.Agent.TrapSinkAddr
	}
	if gotListen != o.trapListen || gotSink != o.trapSink {
		t.Errorf("trap legs = %q/%q, want %q/%q", gotListen, gotSink, o.trapListen, o.trapSink)
	}
}

func checkFilter(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	f := cfg.Notifications.Filter
	if f == nil {
		t.Fatal("--filter-oid/--filter-action were dropped")
	}
	if f.Action != o.filterAction || !reflect.DeepEqual(f.Oids, o.filterOids) {
		t.Errorf("filter = %+v, want action %q oids %v", f, o.filterAction, o.filterOids)
	}
}

func checkMetrics(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	m := cfg.Metrics
	if m.ListenAddr != o.snmpListen || m.TrapSinkAddr != o.snmpTrapSink || m.Community != o.snmpComm {
		t.Errorf("metrics = %+v, want listen %q sink %q community %q",
			m, o.snmpListen, o.snmpTrapSink, o.snmpComm)
	}
	// Config normalization adds the leading dot; the flag value need not
	// carry it (that asymmetry is deliberate, so pin the normalized form).
	if m.BaseOID != "."+o.snmpBaseOID {
		t.Errorf("metrics base OID = %q, want %q", m.BaseOID, "."+o.snmpBaseOID)
	}
}

func checkEngine(t *testing.T, o flagsOpts, cfg *config.Config) {
	t.Helper()
	if cfg.Security.EngineStore != o.engineStore {
		t.Errorf("engine store = %q, want %q", cfg.Security.EngineStore, o.engineStore)
	}
	if cfg.Security.EngineID != o.engineID {
		t.Errorf("engine ID = %q, want %q", cfg.Security.EngineID, o.engineID)
	}
}

// --- access-policy variants ---------------------------------------------

// accessVariant covers both policy shapes: --read-only and the explicit
// write policy. They are mutually exclusive by design, so a sweep that only
// set one would leave half the assembly untested on every path.
type accessVariant struct {
	name   string
	apply  func(*flagsOpts)
	verify func(*testing.T, *config.Config)
}

func accessVariants() []accessVariant {
	return []accessVariant{
		{
			name: "read-only",
			apply: func(o *flagsOpts) {
				o.readOnly = true
				o.writeDefault, o.writeAllow, o.writeDeny = "", nil, nil
			},
			verify: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				if !cfg.Access.ReadOnly {
					t.Error("--read-only was dropped")
				}
				if cfg.Access.WritePolicy != nil {
					t.Errorf("--read-only built a write policy: %+v", cfg.Access.WritePolicy)
				}
				verifyAccessCommon(t, cfg)
			},
		},
		{
			name: "write-policy",
			apply: func(o *flagsOpts) {
				o.readOnly = false
			},
			verify: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				if cfg.Access.ReadOnly {
					t.Error("read-only set without the flag")
				}
				wp := cfg.Access.WritePolicy
				if wp == nil {
					t.Fatal("--write-default/--write-allow/--write-deny were dropped")
				}
				if wp.Default != "allow" {
					t.Errorf("write default = %q, want %q", wp.Default, "allow")
				}
				want := []config.WriteRuleCfg{
					{OID: "1.3.6.1.4.1.99", Action: "allow"},
					{OID: "1.3.6.1.4.1.99.1", Action: "deny"},
				}
				if !reflect.DeepEqual(wp.Rules, want) {
					t.Errorf("write rules = %+v, want %+v", wp.Rules, want)
				}
				verifyAccessCommon(t, cfg)
			},
		},
	}
}

func verifyAccessCommon(t *testing.T, cfg *config.Config) {
	t.Helper()
	if len(cfg.Access.Allow) != 2 || cfg.Access.Allow[1] != "192.0.2.7" {
		t.Errorf("--allow was dropped: %v", cfg.Access.Allow)
	}
	if cfg.Access.RatePerSec != 23 {
		t.Errorf("--rate-per-sec = %d, want 23", cfg.Access.RatePerSec)
	}
	// Validation and runtime share one compiler; compiling here proves the
	// assembled policy is usable, not merely present.
	pol, err := cfg.AccessPolicy()
	if err != nil {
		t.Fatalf("assembled access policy does not compile: %v", err)
	}
	if pol == nil {
		t.Fatal("assembled access policy compiled to nil")
	}
}

// --- flag parsing --------------------------------------------------------

// TestOptsWiresEveryFlag parses the real flag set (register + pflag) and
// compares the resulting flagsOpts with fullOpts. That catches the second
// half of the same bug class: a flag registered and parsed but never copied
// into flagsOpts, which no assembled-config assertion can see.
func TestOptsWiresEveryFlag(t *testing.T) {
	want := fullOpts()
	// The sweep's own completeness tripwire: a field added to flagsOpts
	// must be given a value here, or the case table silently stops
	// covering it.
	v := reflect.ValueOf(want)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("fullOpts leaves %s zero: set it so the sweep proves the flag reaches the config",
				v.Type().Field(i).Name)
		}
	}

	fs := pflag.NewFlagSet("sweep", pflag.ContinueOnError)
	c := register(fs)
	args := []string{
		"--tunnel-mode", want.tunnelMode,
		"--tunnel-addr", want.tunnelAddr,
		"--psk", want.psk,
		"--psk-identity", want.pskIdentity,
		"--psk-ciphersuites", want.pskSuites,
		"--insecure",
		"--max-sessions", "17",
		"--security", want.secMode,
		"--auth-pass", want.authPass,
		"--priv-pass", want.privPass,
		"--engine-store", want.engineStore,
		"--engine-id", want.engineID,
		"--user", want.v3User,
		"--ca-file", want.caFile,
		"--cert-file", want.certFile,
		"--key-file", want.keyFile,
		"--listen", want.listen,
		"--agent", want.agent,
		"--community", want.community,
		"--trap-listen", want.trapListen,
		"--trap-sink", want.trapSink,
		"--filter-action", want.filterAction,
		"--filter-oid", want.filterOids[0],
		"--filter-oid", want.filterOids[1],
		"--allow", want.allow[0],
		"--allow", want.allow[1],
		"--rate-per-sec", "23",
		"--read-only",
		"--write-default", want.writeDefault,
		"--write-allow", want.writeAllow[0],
		"--write-deny", want.writeDeny[0],
		"--metrics-snmp-listen", want.snmpListen,
		"--metrics-snmp-community", want.snmpComm,
		"--metrics-snmp-base-oid", want.snmpBaseOID,
		"--metrics-snmp-trap-sink", want.snmpTrapSink,
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.opts(); !reflect.DeepEqual(got, want) {
		// Per-field diff: the whole-struct message is unreadable.
		gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
		for i := 0; i < wv.NumField(); i++ {
			if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
				t.Errorf("%s = %v, want %v (flag parsed but not copied into flagsOpts?)",
					wv.Type().Field(i).Name, gv.Field(i).Interface(), wv.Field(i).Interface())
			}
		}
	}
}

// splitList mirrors the manager's comma-separated --tunnel-addr parsing.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
