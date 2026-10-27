// Command snmp-shield runs one instance of the SNMP securing proxy.
// The role is chosen by subcommand: manager or agent. Each subcommand can
// be configured either by a YAML file (--config) or entirely by flags for
// plug-and-play deployments without config files.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/proxy"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

const version = "0.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("snmp-shield %s\n", version)
		return 0
	case "manager", "agent", "gateway":
		return runRole(os.Args[1], os.Args[2:])
	case "validate":
		return runValidate(os.Args[2:])
	case "selftest":
		return runSelftest(os.Args[2:])
	case "genpsk":
		return genPSK()
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

// parsePskCiphersuites splits the comma-separated --psk-ciphersuites
// flag into a list (empty flag = nil, default applies). Name validity
// is checked by Config.Validate.
func parsePskCiphersuites(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// genPSK prints a fresh random 32-byte pre-shared key in hex form.
func genPSK() int {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "genpsk: %v\n", err)
		return 1
	}
	fmt.Println(hex.EncodeToString(buf))
	return 0
}

// cliFlags bundles every flag the role/validate/selftest subcommands
// accept. register returns the parsed values after FlagSet.Parse.
type cliFlags struct {
	fs *pflag.FlagSet

	configPath    *string
	metricsAddr   *string
	logLevel      *string
	dev           *bool
	tunnelMode    *string
	tunnelAddr    *string
	psk           *string
	pskIdentity   *string
	pskSuites     *string
	insecure      *bool
	secMode       *string
	authPass      *string
	privPass      *string
	v3User        *string
	engineStore   *string
	caFile        *string
	certFile      *string
	keyFile       *string
	listen        *string
	agent         *string
	community     *string
	trapListen    *string
	trapSink      *string
	filterAction  *string
	filterOID     *[]string
	allow         *[]string
	ratePerSec    *int
	readOnly      *bool
	writeDefault  *string
	writeAllow    *[]string
	writeDeny     *[]string
	snmpListen    *string
	snmpCommunity *string
	snmpBaseOID   *string
	snmpTrapSink  *string
	jsonOut       *bool
	selftestProbe *bool
}

// register defines the full flag set shared by manager/agent/gateway,
// validate and selftest (unknown flags are simply ignored by the
// non-role subcommands).
func register(fs *pflag.FlagSet) cliFlags {
	var c cliFlags
	c.fs = fs
	c.configPath = fs.String("config", "", "path to YAML config file (either --config or direct flags)")
	c.metricsAddr = fs.String("metrics-addr", "", "Prometheus metrics listen address (e.g. 127.0.0.1:9672)")
	c.logLevel = fs.String("log-level", "info", "log level: debug, info, error")
	c.dev = fs.Bool("dev", false, "development logging (console output)")

	// direct-flags mode (no --config): tunnel
	c.tunnelMode = fs.String("tunnel-mode", "dtls", "secured-segment transport: dtls (UDP) or tls (TCP)")
	c.tunnelAddr = fs.String("tunnel-addr", "", "tunnel endpoint(s): manager role dials comma-separated addresses (HA failover, most preferred first); agent role listens on ip:port")
	c.psk = fs.String("psk", "", "pre-shared key for the tunnel (hex; generate with `snmp-shield genpsk`)")
	c.pskIdentity = fs.String("psk-identity", "snmp-shield", "PSK identity string")
	c.pskSuites = fs.String("psk-ciphersuites", "", "DTLS PSK ciphersuites, comma-separated, most preferred first (aes128-ccm-8, aes256-ccm-8, aes128-ccm, aes128-gcm, aes128-cbc; default aes128-ccm-8)")
	c.insecure = fs.Bool("insecure", false, "skip tunnel certificate verification (tls mode only; never in production)")

	// direct-flags mode: usm-translate security
	c.secMode = fs.String("security", "usm-translate", "security mode when using flags: usm-translate or passthrough (gateway: usm-gateway, usm-manager-gateway or tsm-gateway)")
	c.authPass = fs.String("auth-pass", "", "v3 authentication passphrase (usm-translate/gateway mode; user 'proxy', SHA, AES)")
	c.privPass = fs.String("priv-pass", "", "v3 privacy passphrase (usm-translate/gateway mode)")
	c.v3User = fs.String("user", "", "v3 username for usm-manager-gateway mode (the REAL AGENT's configured user; default 'proxy')")
	c.engineStore = fs.String("engine-store", "", "path to the persistent engine boots store (usm-translate/usm-gateway; YAML mode requires it, flags mode defaults to memory-only with a warning)")

	// direct-flags mode: certificate material (tsm tunnel / tsm-gateway)
	c.caFile = fs.String("ca-file", "", "CA certificate PEM file to verify peers (tsm-gateway)")
	c.certFile = fs.String("cert-file", "", "certificate PEM file to present (tsm-gateway)")
	c.keyFile = fs.String("key-file", "", "private key PEM file (tsm-gateway)")

	// direct-flags mode: role specifics
	c.listen = fs.String("listen", "", "clear SNMP listener (manager role: requests; also used for traps with --trap-listen)")
	c.agent = fs.String("agent", "", "real SNMP agent address ip:port (agent role)")
	c.community = fs.String("community", "public", "SNMP community (manager role: trap sink/source; agent role: toward the real agent)")
	c.trapListen = fs.String("trap-listen", "", "clear trap listener ip:port (optional, both roles)")
	c.trapSink = fs.String("trap-sink", "", "trap sink ip:port (manager role: where tunnel notifications are delivered; agent role: local sink for tunnel traps)")

	// direct-flags mode: notification filtering
	c.filterAction = fs.String("filter-action", "allow", "notification filter action: allow or deny")
	c.filterOID = fs.StringArray("filter-oid", nil, "notification filter OID prefix (repeatable, e.g. --filter-oid 1.3.6.1.4.1.8072)")
	// access policy (front-leg clients, rate, writes)
	c.allow = fs.StringArray("allow", nil, "client allow-list entry: bare IP or CIDR range (repeatable; empty = every client)")
	c.ratePerSec = fs.Int("rate-per-sec", 0, "per-client request rate limit (0 = unlimited)")
	c.readOnly = fs.Bool("read-only", false, "refuse every SET (write) request")
	c.writeDefault = fs.String("write-default", "", "write policy verdict for objects no rule covers: allow or deny (default deny; setting this enables the policy)")
	c.writeAllow = fs.StringArray("write-allow", nil, "writable OID subtree (repeatable)")
	c.writeDeny = fs.StringArray("write-deny", nil, "forbidden OID subtree, wins over allow (repeatable)")

	// direct-flags mode: SNMP metrics interface (health MIB + event traps)
	c.snmpListen = fs.String("metrics-snmp-listen", "", "SNMP health MIB listen address ip:port (GET/GETNEXT; enables the SNMP metrics agent)")
	c.snmpCommunity = fs.String("metrics-snmp-community", "public", "SNMP community for the health MIB and event traps")
	c.snmpBaseOID = fs.String("metrics-snmp-base-oid", ".1.3.6.1.4.1.58427.1", "SNMP metrics MIB base OID (enterprise OID)")
	c.snmpTrapSink = fs.String("metrics-snmp-trap-sink", "", "trap sink ip:port for tunnel lifecycle events (tunnel up/down, HA failover)")

	// validate/selftest only
	c.jsonOut = fs.Bool("json", false, "validate: machine-readable JSON output (for tooling / web UIs)")
	c.selftestProbe = fs.Bool("probe", true, "selftest: run network probes (tunnel dial / SNMP GET); --probe=false checks config and local files only")
	return c
}

// opts converts the parsed flags to the flagsOpts used by flagsConfig.
func (c cliFlags) opts() flagsOpts {
	return flagsOpts{
		tunnelMode:   *c.tunnelMode,
		tunnelAddr:   *c.tunnelAddr,
		psk:          *c.psk,
		pskIdentity:  *c.pskIdentity,
		pskSuites:    *c.pskSuites,
		insecure:     *c.insecure,
		secMode:      *c.secMode,
		authPass:     *c.authPass,
		privPass:     *c.privPass,
		v3User:       *c.v3User,
		engineStore:  *c.engineStore,
		caFile:       *c.caFile,
		certFile:     *c.certFile,
		keyFile:      *c.keyFile,
		listen:       *c.listen,
		agent:        *c.agent,
		community:    *c.community,
		trapListen:   *c.trapListen,
		trapSink:     *c.trapSink,
		filterAction: *c.filterAction,
		filterOids:   *c.filterOID,
		allow:        *c.allow,
		ratePerSec:   *c.ratePerSec,
		readOnly:     *c.readOnly,
		writeDefault: *c.writeDefault,
		writeAllow:   *c.writeAllow,
		writeDeny:    *c.writeDeny,
		snmpListen:   *c.snmpListen,
		snmpComm:     *c.snmpCommunity,
		snmpBaseOID:  *c.snmpBaseOID,
		snmpTrapSink: *c.snmpTrapSink,
	}
}

func runRole(role string, args []string) int {
	fs := pflag.NewFlagSet(role, pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log, err := observ.Log(*c.logLevel, *c.dev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	var r config.Role
	switch role {
	case "manager":
		r = config.RoleManager
	case "agent":
		r = config.RoleAgent
	case "gateway":
		r = config.RoleGateway
	}

	var cfg *config.Config
	if *c.configPath != "" {
		cfg, err = config.Load(*c.configPath, r)
		if err != nil {
			log.Error("load config", zap.Error(err))
			return 1
		}
	} else {
		cfg, err = flagsConfig(r, c.opts())
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
	}

	startFields := []zap.Field{
		zap.String("role", role),
		zap.String("security_mode", cfg.Security.Mode),
	}
	if role != "gateway" {
		startFields = append(startFields, zap.String("tunnel_mode", cfg.Tunnel.Mode))
	}
	log.Info("starting snmp-shield", startFields...)

	err = proxy.Run(proxy.Options{
		Config:      cfg,
		MetricsAddr: *c.metricsAddr,
		Log:         log,
		Version:     version,
		// SIGHUP re-reads this file and applies the reloadable parts
		// (access policy). Empty in flags mode = logged no-op.
		ConfigPath: *c.configPath,
	})
	if err != nil {
		log.Error("proxy exited", zap.Error(err))
		return 1
	}
	return 0
}

// flagsOpts carries the direct-flag values for building a Config without
// a YAML file.
type flagsOpts struct {
	tunnelMode   string
	tunnelAddr   string
	psk          string
	pskIdentity  string
	pskSuites    string
	insecure     bool
	secMode      string
	authPass     string
	privPass     string
	engineStore  string
	v3User       string
	caFile       string
	certFile     string
	keyFile      string
	listen       string
	agent        string
	community    string
	trapListen   string
	trapSink     string
	filterAction string
	filterOids   []string
	allow        []string
	ratePerSec   int
	readOnly     bool
	writeDefault string
	writeAllow   []string
	writeDeny    []string
	snmpListen   string
	snmpComm     string
	snmpBaseOID  string
	snmpTrapSink string
}

// snmpMetrics builds the config Metrics section from flags (zero value
// when none of the --metrics-snmp-* flags are set beyond defaults).
func snmpMetrics(o flagsOpts) config.MetricsRole {
	return config.MetricsRole{
		ListenAddr:   o.snmpListen,
		Community:    o.snmpComm,
		BaseOID:      o.snmpBaseOID,
		TrapSinkAddr: o.snmpTrapSink,
	}
}

// trapFilter builds the config Notifications filter from flags (nil when
// no --filter-oid is given).
func trapFilter(o flagsOpts) (*config.NotifyFilter, error) {
	if len(o.filterOids) == 0 {
		return nil, nil
	}
	return &config.NotifyFilter{Action: o.filterAction, Oids: o.filterOids}, nil
}

// accessPolicy builds the config Access section from flags: the client
// allow-list, the per-client rate limit and the write policy (--read-only,
// or --write-default with --write-allow/--write-deny subtrees).
func accessPolicy(o flagsOpts) (*config.Access, error) {
	a := &config.Access{
		Allow:      o.allow,
		RatePerSec: o.ratePerSec,
		ReadOnly:   o.readOnly,
	}
	hasRules := len(o.writeAllow) > 0 || len(o.writeDeny) > 0
	if hasRules || o.writeDefault != "" {
		if o.readOnly {
			if hasRules {
				return nil, fmt.Errorf("--read-only and --write-allow/--write-deny are mutually exclusive")
			}
			return a, nil
		}
		// An explicit policy: --write-default (deny unless set) plus the
		// allow/deny subtrees. Deny rules always win.
		def := o.writeDefault
		if def == "" {
			def = "deny"
		}
		wp := &config.WritePolicyCfg{Default: def}
		for _, oid := range o.writeAllow {
			wp.Rules = append(wp.Rules, config.WriteRuleCfg{OID: oid, Action: "allow"})
		}
		for _, oid := range o.writeDeny {
			wp.Rules = append(wp.Rules, config.WriteRuleCfg{OID: oid, Action: "deny"})
		}
		a.WritePolicy = wp
	}
	if len(a.Allow) == 0 && a.RatePerSec == 0 && !a.ReadOnly && a.WritePolicy == nil {
		return nil, nil
	}
	return a, nil
}

// flagsConfig assembles a validated Config from direct flags (plug-and-play
// deployment without a YAML file).
func flagsConfig(r config.Role, o flagsOpts) (*config.Config, error) {
	// Gateway role: single-box gateway — no tunnel, no PSK. The front leg
	// terminates SNMP security directly from third-party clients;
	// authenticated requests are relayed as clear v2c to the legacy agent.
	if r == config.RoleGateway {
		switch o.secMode {
		case "usm-gateway", "tsm-gateway", "usm-manager-gateway":
		case "usm-translate", "passthrough":
			return nil, fmt.Errorf("--security %s is not valid for the gateway role (use usm-gateway, usm-manager-gateway or tsm-gateway)", o.secMode)
		default:
			return nil, fmt.Errorf("--security must be usm-gateway, usm-manager-gateway or tsm-gateway for the gateway role, got %q", o.secMode)
		}
		cfg := &config.Config{Role: r}
		cfg.Gateway = config.GatewayRole{
			ListenAddr:     o.listen,
			AgentAddr:      o.agent,
			AgentCommunity: o.community,
			TrapListenAddr: o.trapListen,
			TrapSinkAddr:   o.trapSink,
		}
		switch o.secMode {
		case "usm-gateway":
			if o.authPass == "" || o.privPass == "" {
				return nil, fmt.Errorf("--auth-pass and --priv-pass are required in usm-gateway mode (v3 user 'proxy', SHA, AES)")
			}
			// Either leg pair (or both): the request path and/or the
			// notification path.
			if (o.listen == "") != (o.agent == "") {
				return nil, fmt.Errorf("--listen and --agent must be given together (request path)")
			}
			if (o.trapListen == "") != (o.trapSink == "") {
				return nil, fmt.Errorf("--trap-listen and --trap-sink must be given together (notification path)")
			}
			if o.listen == "" && o.trapListen == "" {
				return nil, fmt.Errorf("usm-gateway mode needs --listen + --agent (request path) or --trap-listen + --trap-sink (notification path)")
			}
			cfg.Security = config.Security{
				Mode: "usm-gateway",
				Users: []config.UserCfg{{
					Name:           "proxy",
					AuthProtocol:   "sha",
					AuthPassphrase: o.authPass,
					PrivProtocol:   "aes",
					PrivPassphrase: o.privPass,
				}},
			}
		case "usm-manager-gateway":
			if o.authPass == "" || o.privPass == "" {
				return nil, fmt.Errorf("--auth-pass and --priv-pass are required in usm-manager-gateway mode (the REAL AGENT's v3 credentials)")
			}
			if o.listen == "" {
				return nil, fmt.Errorf("--listen is required for the gateway role (legacy manager front listener ip:port)")
			}
			if o.agent == "" {
				return nil, fmt.Errorf("--agent is required for the gateway role (real v3 agent ip:port)")
			}
			user := o.v3User
			if user == "" {
				user = "proxy"
			}
			cfg.Security = config.Security{
				Mode: "usm-manager-gateway",
				Users: []config.UserCfg{{
					Name:           user,
					AuthProtocol:   "sha",
					AuthPassphrase: o.authPass,
					PrivProtocol:   "aes",
					PrivPassphrase: o.privPass,
				}},
			}
		case "tsm-gateway":
			if o.certFile == "" || o.keyFile == "" || o.caFile == "" {
				return nil, fmt.Errorf("--cert-file, --key-file and --ca-file are required in tsm-gateway mode (DTLS front leg, client certificate verification)")
			}
			if o.listen == "" {
				return nil, fmt.Errorf("--listen is required for the gateway role (SNMP front listener ip:port)")
			}
			if o.agent == "" {
				return nil, fmt.Errorf("--agent is required for the gateway role (legacy agent ip:port)")
			}
			cfg.Security = config.Security{Mode: "tsm-gateway"}
			cfg.Tunnel = config.Tunnel{
				CAFile:   o.caFile,
				CertFile: o.certFile,
				KeyFile:  o.keyFile,
			}
		}
		// Notification filtering (gateway role, flags mode).
		if filt, ferr := trapFilter(o); ferr != nil {
			return nil, ferr
		} else if filt != nil {
			cfg.Notifications = config.Notifications{Filter: filt}
		}
		cfg.Metrics = snmpMetrics(o)
		// Engine state: flags mode is the plug-and-play path, so an
		// unnamed store means memory-only — explicitly (YAML configs must
		// name a persistent store; see config.Validate).
		cfg.Security.EngineStore = o.engineStore
		cfg.Security.EphemeralEngine = o.engineStore == ""
		cfg.Defaults()
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	if o.tunnelAddr == "" {
		return nil, fmt.Errorf("--tunnel-addr is required (tunnel endpoint ip:port)")
	}
	if o.psk == "" {
		return nil, fmt.Errorf("--psk is required (generate one with `snmp-shield genpsk`)")
	}
	if o.secMode != "usm-translate" && o.secMode != "passthrough" {
		if o.secMode == "tsm" {
			return nil, fmt.Errorf("--security tsm requires a config file (see configs/manager-tsm.yaml + agent-tsm.yaml); flags mode supports usm-translate and passthrough")
		}
		return nil, fmt.Errorf("--security must be usm-translate or passthrough, got %q", o.secMode)
	}

	cfg := &config.Config{Role: r}
	cfg.Tunnel = config.Tunnel{
		Mode:               o.tunnelMode,
		PSKIdentity:        o.pskIdentity,
		PSK:                "hex:" + o.psk,
		PskCiphersuites:    parsePskCiphersuites(o.pskSuites),
		InsecureSkipVerify: o.insecure,
	}
	cfg.Security = config.Security{Mode: o.secMode}

	switch o.secMode {
	case "usm-translate":
		if o.authPass == "" || o.privPass == "" {
			return nil, fmt.Errorf("--auth-pass and --priv-pass are required in usm-translate mode (same values on both proxies)")
		}
		cfg.Security.Users = []config.UserCfg{{
			Name:           "proxy",
			AuthProtocol:   "sha",
			AuthPassphrase: o.authPass,
			PrivProtocol:   "aes",
			PrivPassphrase: o.privPass,
			Community:      o.community,
		}}
	}

	switch r {
	case config.RoleManager:
		if o.listen == "" {
			return nil, fmt.Errorf("--listen is required for the manager role (clear SNMP listener ip:port)")
		}
		// --tunnel-addr accepts a comma-separated list (HA failover,
		// most preferred first).
		for _, a := range strings.Split(o.tunnelAddr, ",") {
			if a = strings.TrimSpace(a); a != "" {
				cfg.Tunnel.DialAddrs = append(cfg.Tunnel.DialAddrs, a)
			}
		}
		cfg.Manager = config.ManagerRole{
			ListenAddr:     o.listen,
			TrapSinkAddr:   o.trapSink,
			TrapListenAddr: o.trapListen,
		}
	case config.RoleAgent:
		if o.agent == "" {
			return nil, fmt.Errorf("--agent is required for the agent role (real SNMP agent ip:port)")
		}
		cfg.Tunnel.ListenAddr = o.tunnelAddr
		cfg.Agent = config.AgentRole{
			AgentAddr:      o.agent,
			TrapListenAddr: o.trapListen,
			TrapSinkAddr:   o.trapSink,
		}
		// agent role: community is used toward the real agent for
		// translated requests; mirror it into the user profile.
		if len(cfg.Security.Users) > 0 {
			cfg.Security.Users[0].Community = o.community
		}
	}

	// Notification filtering (both roles, flags mode).
	if filt, ferr := trapFilter(o); ferr != nil {
		return nil, ferr
	} else if filt != nil {
		cfg.Notifications = config.Notifications{Filter: filt}
	}
	acc, aerr := accessPolicy(o)
	if aerr != nil {
		return nil, aerr
	}
	if acc != nil {
		cfg.Access = *acc
	}
	cfg.Metrics = snmpMetrics(o)
	// Engine state: flags mode is the plug-and-play path (smoke tests,
	// evaluations). Without --engine-store the engine state is memory-only,
	// which must be EXPLICIT — YAML configs are required to name a
	// persistent store (anti-rollback). The proxy logs the warning at
	// startup.
	cfg.Security.EngineStore = o.engineStore
	cfg.Security.EphemeralEngine = o.engineStore == ""
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func usage(w *os.File) {
	fmt.Fprintf(w, `snmp-shield — SNMP securing proxy

Usage (config file):
  snmp-shield manager --config <file> [--metrics-addr <addr>]
  snmp-shield agent   --config <file> [--metrics-addr <addr>]
  snmp-shield gateway --config <file> [--metrics-addr <addr>]

Usage (flags, no config file — plug and play):
  snmp-shield manager --tunnel-addr <agent-proxy:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --listen <ip:port> \
      [--trap-sink <ip:port>] [--trap-listen <ip:port>]
  snmp-shield agent --tunnel-addr <ip:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --agent <real-agent:port> \
      [--community <comm>] [--trap-listen <ip:port>] [--trap-sink <ip:port>]

Usage (gateway, single box — no second proxy, standard clients):
  snmp-shield gateway --security usm-gateway --listen <ip:port> \
      --agent <real-agent:port> --auth-pass <pw> --priv-pass <pw> \
      [--community <comm>] [--trap-listen <ip:port>] [--trap-sink <ip:port>]
  snmp-shield gateway --security tsm-gateway --listen <ip:port> \
      --agent <real-agent:port> --ca-file <ca.pem> --cert-file <cert.pem> \
      --key-file <key.pem> [--community <comm>] \
      [--trap-listen <ip:port>] [--trap-sink <ip:port>]
  snmp-shield gateway --security usm-gateway --trap-listen <ip:port> \
      --trap-sink <manager-trap-receiver:port> \
      --auth-pass <pw> --priv-pass <pw>        # notification-only (manager leg)
  snmp-shield gateway --security usm-manager-gateway --listen <ip:port> \
      --agent <v3-agent:port> --auth-pass <pw> --priv-pass <pw> \
      [--trap-listen <ip:port>] [--trap-sink <ip:port>]
                                              # legacy manager front (v3 out)

Other commands:
  snmp-shield validate --role <manager|agent|gateway> (same flags as the role)
      [--config <file>] [--json]
      check a configuration without running (pre-apply for tooling /
      web UIs); pre-flights certs, keys and the engine store
  snmp-shield selftest --role <manager|agent|gateway> (same flags as the role)
      [--config <file>] [--json] [--probe=false]
      validate + probe the environment: cert expiry, engine store,
      tunnel handshake (manager), SNMP GET to the real agent
      (agent/gateway)
  snmp-shield genpsk     print a fresh random pre-shared key (hex)
  snmp-shield version

Notification filtering (flags mode): --filter-oid <prefix> (repeatable)
with --filter-action allow|deny drops notifications whose trap OID does
not pass the filter before they are relayed.

SNMP metrics interface (flags mode): --metrics-snmp-listen <ip:port>
serves a small read-only SNMPv2c health MIB (GET/GETNEXT: identity,
tunnel state, counters) and --metrics-snmp-trap-sink <ip:port> emits
v2c traps on tunnel lifecycle changes (up/down, HA failover).
--metrics-snmp-community (default "public") and
--metrics-snmp-base-oid (default .1.3.6.1.4.1.58427.1) apply to both.
Prometheus metrics (--metrics-addr) stay available alongside.

The manager instance listens for clear SNMP from managers and dials the
secured tunnel; the agent instance listens on the tunnel and forwards to
the real SNMP agent. Run one instance on each side of the secured line.
Both sides must share the same --psk, --auth-pass and --priv-pass.
The gateway instance is a single box with no tunnel: managers talk to it
directly and authenticated requests are relayed as clear v2c to the
legacy agent. usm-gateway terminates SNMPv3 USM (user 'proxy') from any
standard manager and also supports notification-only deployments
(--trap-listen + --trap-sink instead of --listen + --agent: clear device
traps/informs are wrapped into authenticated v3 notifications toward the
manager's trap receiver, informs confirmed end-to-end); tsm-gateway
speaks SNMP-over-DTLS (RFC 6353) with certificate-based client
authentication; usm-manager-gateway is the reverse direction — a legacy
v1/v2c manager in front and a v3-capable agent behind: clear requests
are re-issued as authenticated v3 (USM authPriv, RFC 3414 discovery)
toward the real agent, agent traps/informs are verified, unwrapped and
relayed as clear v1/v2c to the manager's trap receiver (informs
confirmed by the proxy). 100%% standard SNMP on every wire.
`)
}
