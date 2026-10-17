// Command snmp-proxy runs one instance of the SNMP securing proxy.
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

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/proxy"
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
		fmt.Printf("snmp-proxy %s\n", version)
		return 0
	case "manager", "agent", "gateway":
		return runRole(os.Args[1], os.Args[2:])
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

func runRole(role string, args []string) int {
	fs := pflag.NewFlagSet(role, pflag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to YAML config file (either --config or direct flags)")
	metricsAddr := fs.String("metrics-addr", "", "Prometheus metrics listen address (e.g. 127.0.0.1:9672)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, error")
	dev := fs.Bool("dev", false, "development logging (console output)")

	// direct-flags mode (no --config): tunnel
	tunnelMode := fs.String("tunnel-mode", "dtls", "secured-segment transport: dtls (UDP) or tls (TCP)")
	tunnelAddr := fs.String("tunnel-addr", "", "tunnel endpoint(s): manager role dials comma-separated addresses (HA failover, most preferred first); agent role listens on ip:port")
	psk := fs.String("psk", "", "pre-shared key for the tunnel (hex; generate with `snmp-proxy genpsk`)")
	pskIdentity := fs.String("psk-identity", "snmp-proxy", "PSK identity string")
	pskSuites := fs.String("psk-ciphersuites", "", "DTLS PSK ciphersuites, comma-separated, most preferred first (aes128-ccm-8, aes256-ccm-8, aes128-ccm, aes128-gcm, aes128-cbc; default aes128-ccm-8)")
	insecure := fs.Bool("insecure", false, "skip tunnel certificate verification (tls mode only; never in production)")

	// direct-flags mode: usm-translate security
	secMode := fs.String("security", "usm-translate", "security mode when using flags: usm-translate or passthrough (gateway: usm-gateway, tsm-gateway or usm-manager)")
	authPass := fs.String("auth-pass", "", "v3 authentication passphrase (usm-translate/gateway mode; user 'proxy', SHA, AES)")
	privPass := fs.String("priv-pass", "", "v3 privacy passphrase (usm-translate/gateway mode)")

	// direct-flags mode: certificate material (tsm tunnel / tsm-gateway)
	caFile := fs.String("ca-file", "", "CA certificate PEM file to verify peers (tsm-gateway)")
	certFile := fs.String("cert-file", "", "certificate PEM file to present (tsm-gateway)")
	keyFile := fs.String("key-file", "", "private key PEM file (tsm-gateway)")

	// direct-flags mode: role specifics
	listen := fs.String("listen", "", "clear SNMP listener (manager role: requests; also used for traps with --trap-listen)")
	agent := fs.String("agent", "", "real SNMP agent address ip:port (agent role)")
	community := fs.String("community", "public", "SNMP community (manager role: trap sink/source; agent role: toward the real agent)")
	trapListen := fs.String("trap-listen", "", "clear trap listener ip:port (optional, both roles)")
	trapSink := fs.String("trap-sink", "", "trap sink ip:port (manager role: where tunnel notifications are delivered; agent role: local sink for tunnel traps)")

	// direct-flags mode: notification filtering
	filterAction := fs.String("filter-action", "allow", "notification filter action: allow or deny")
	filterOID := fs.StringArray("filter-oid", nil, "notification filter OID prefix (repeatable, e.g. --filter-oid 1.3.6.1.4.1.8072)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	log, err := observ.Log(*logLevel, *dev)
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
	if *cfgPath != "" {
		cfg, err = config.Load(*cfgPath, r)
		if err != nil {
			log.Error("load config", zap.Error(err))
			return 1
		}
	} else {
		cfg, err = flagsConfig(r, flagsOpts{
			tunnelMode:   *tunnelMode,
			tunnelAddr:   *tunnelAddr,
			psk:          *psk,
			pskIdentity:  *pskIdentity,
			pskSuites:    *pskSuites,
			insecure:     *insecure,
			secMode:      *secMode,
			authPass:     *authPass,
			privPass:     *privPass,
			caFile:       *caFile,
			certFile:     *certFile,
			keyFile:      *keyFile,
			listen:       *listen,
			agent:        *agent,
			community:    *community,
			trapListen:   *trapListen,
			trapSink:     *trapSink,
			filterAction: *filterAction,
			filterOids:   *filterOID,
		})
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
	log.Info("starting snmp-proxy", startFields...)

	err = proxy.Run(proxy.Options{
		Config:      cfg,
		MetricsAddr: *metricsAddr,
		Log:         log,
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
}

// trapFilter builds the config Notifications filter from flags (nil when
// no --filter-oid is given).
func trapFilter(o flagsOpts) (*config.NotifyFilter, error) {
	if len(o.filterOids) == 0 {
		return nil, nil
	}
	return &config.NotifyFilter{Action: o.filterAction, Oids: o.filterOids}, nil
}

// flagsConfig assembles a validated Config from direct flags (plug-and-play
// deployment without a YAML file).
func flagsConfig(r config.Role, o flagsOpts) (*config.Config, error) {
	// Gateway role: single-box gateway — no tunnel, no PSK. The front leg
	// terminates SNMP security directly from third-party clients;
	// authenticated requests are relayed as clear v2c to the legacy agent.
	if r == config.RoleGateway {
		if o.listen == "" {
			return nil, fmt.Errorf("--listen is required for the gateway role (SNMP front listener ip:port)")
		}
		if o.agent == "" {
			return nil, fmt.Errorf("--agent is required for the gateway role (legacy agent ip:port)")
		}
		switch o.secMode {
		case "usm-gateway", "tsm-gateway", "usm-manager":
		case "usm-translate", "passthrough":
			return nil, fmt.Errorf("--security %s is not valid for the gateway role (use usm-gateway, tsm-gateway or usm-manager)", o.secMode)
		default:
			return nil, fmt.Errorf("--security must be usm-gateway, tsm-gateway or usm-manager for the gateway role, got %q", o.secMode)
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
		case "tsm-gateway":
			if o.certFile == "" || o.keyFile == "" || o.caFile == "" {
				return nil, fmt.Errorf("--cert-file, --key-file and --ca-file are required in tsm-gateway mode (DTLS front leg, client certificate verification)")
			}
			cfg.Security = config.Security{Mode: "tsm-gateway"}
			cfg.Tunnel = config.Tunnel{
				CAFile:   o.caFile,
				CertFile: o.certFile,
				KeyFile:  o.keyFile,
			}
		case "usm-manager":
			if o.authPass == "" || o.privPass == "" {
				return nil, fmt.Errorf("--auth-pass and --priv-pass are required in usm-manager mode (v3 user 'proxy', SHA, AES)")
			}
			if o.trapListen == "" || o.trapSink == "" {
				return nil, fmt.Errorf("--trap-listen and --trap-sink are required in usm-manager mode (clear device notifications in, manager's v3 trap receiver out)")
			}
			cfg.Security = config.Security{
				Mode: "usm-manager",
				Users: []config.UserCfg{{
					Name:           "proxy",
					AuthProtocol:   "sha",
					AuthPassphrase: o.authPass,
					PrivProtocol:   "aes",
					PrivPassphrase: o.privPass,
				}},
			}
		}
		// Notification filtering (gateway role, flags mode).
		if filt, ferr := trapFilter(o); ferr != nil {
			return nil, ferr
		} else if filt != nil {
			cfg.Notifications = config.Notifications{Filter: filt}
		}
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
		return nil, fmt.Errorf("--psk is required (generate one with `snmp-proxy genpsk`)")
	}
	if o.secMode != "usm-translate" && o.secMode != "passthrough" {
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
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func usage(w *os.File) {
	fmt.Fprintf(w, `snmp-proxy — SNMP securing proxy

Usage (config file):
  snmp-proxy manager --config <file> [--metrics-addr <addr>]
  snmp-proxy agent   --config <file> [--metrics-addr <addr>]
  snmp-proxy gateway --config <file> [--metrics-addr <addr>]

Usage (flags, no config file — plug and play):
  snmp-proxy manager --tunnel-addr <agent-proxy:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --listen <ip:port> \
      [--trap-sink <ip:port>] [--trap-listen <ip:port>]
  snmp-proxy agent --tunnel-addr <ip:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --agent <real-agent:port> \
      [--community <comm>] [--trap-listen <ip:port>] [--trap-sink <ip:port>]

Usage (gateway, single box — no second proxy, standard clients):
  snmp-proxy gateway --security usm-gateway --listen <ip:port> \
      --agent <real-agent:port> --auth-pass <pw> --priv-pass <pw> \
      [--community <comm>] [--trap-listen <ip:port>] [--trap-sink <ip:port>]
  snmp-proxy gateway --security tsm-gateway --listen <ip:port> \
      --agent <real-agent:port> --ca-file <ca.pem> --cert-file <cert.pem> \
      --key-file <key.pem> [--community <comm>] \
      [--trap-listen <ip:port>] [--trap-sink <ip:port>]
  snmp-proxy gateway --security usm-manager \
      --trap-listen <ip:port> --trap-sink <manager-trap-receiver:port> \
      --auth-pass <pw> --priv-pass <pw>

Other commands:
  snmp-proxy genpsk     print a fresh random pre-shared key (hex)
  snmp-proxy version

Notification filtering (flags mode): --filter-oid <prefix> (repeatable)
with --filter-action allow|deny drops notifications whose trap OID does
not pass the filter before they are relayed.

The manager instance listens for clear SNMP from managers and dials the
secured tunnel; the agent instance listens on the tunnel and forwards to
the real SNMP agent. Run one instance on each side of the secured line.
Both sides must share the same --psk, --auth-pass and --priv-pass.
The gateway instance is a single box with no tunnel: managers talk to it
directly and authenticated requests are relayed as clear v2c to the
legacy agent. usm-gateway terminates SNMPv3 USM (user 'proxy') from any
standard manager; tsm-gateway speaks SNMP-over-DTLS (RFC 6353) with
certificate-based client authentication; usm-manager protects the
manager leg: clear device traps/informs are wrapped into authenticated
v3 notifications toward the manager's trap receiver. 100%% standard
SNMP on every wire.
`)
}
