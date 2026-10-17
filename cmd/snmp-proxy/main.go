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
	case "manager", "agent":
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
	tunnelAddr := fs.String("tunnel-addr", "", "tunnel endpoint: dial (manager role) or listen (agent role) address ip:port")
	psk := fs.String("psk", "", "pre-shared key for the tunnel (hex; generate with `snmp-proxy genpsk`)")
	pskIdentity := fs.String("psk-identity", "snmp-proxy", "PSK identity string")
	insecure := fs.Bool("insecure", false, "skip tunnel certificate verification (tls mode only; never in production)")

	// direct-flags mode: usm-translate security
	secMode := fs.String("security", "usm-translate", "security mode when using flags: usm-translate or passthrough")
	authPass := fs.String("auth-pass", "", "v3 authentication passphrase (usm-translate mode; user 'proxy', SHA, AES)")
	privPass := fs.String("priv-pass", "", "v3 privacy passphrase (usm-translate mode)")

	// direct-flags mode: role specifics
	listen := fs.String("listen", "", "clear SNMP listener (manager role: requests; also used for traps with --trap-listen)")
	agent := fs.String("agent", "", "real SNMP agent address ip:port (agent role)")
	community := fs.String("community", "public", "SNMP community (manager role: trap sink/source; agent role: toward the real agent)")
	trapListen := fs.String("trap-listen", "", "clear trap listener ip:port (optional, both roles)")
	trapSink := fs.String("trap-sink", "", "trap sink ip:port (manager role: where tunnel notifications are delivered; agent role: local sink for tunnel traps)")

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
			tunnelMode:  *tunnelMode,
			tunnelAddr:  *tunnelAddr,
			psk:         *psk,
			pskIdentity: *pskIdentity,
			insecure:    *insecure,
			secMode:     *secMode,
			authPass:    *authPass,
			privPass:    *privPass,
			listen:      *listen,
			agent:       *agent,
			community:   *community,
			trapListen:  *trapListen,
			trapSink:    *trapSink,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
	}

	log.Info("starting snmp-proxy",
		zap.String("role", role),
		zap.String("tunnel_mode", cfg.Tunnel.Mode),
		zap.String("security_mode", cfg.Security.Mode))

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
	tunnelMode  string
	tunnelAddr  string
	psk         string
	pskIdentity string
	insecure    bool
	secMode     string
	authPass    string
	privPass    string
	listen      string
	agent       string
	community   string
	trapListen  string
	trapSink    string
}

// flagsConfig assembles a validated Config from direct flags (plug-and-play
// deployment without a YAML file).
func flagsConfig(r config.Role, o flagsOpts) (*config.Config, error) {
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
		cfg.Tunnel.DialAddr = o.tunnelAddr
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

Usage (flags, no config file — plug and play):
  snmp-proxy manager --tunnel-addr <agent-proxy:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --listen <ip:port> \
      [--trap-sink <ip:port>] [--trap-listen <ip:port>]
  snmp-proxy agent --tunnel-addr <ip:port> --psk <hex> \
      --auth-pass <pw> --priv-pass <pw> --agent <real-agent:port> \
      [--community <comm>] [--trap-listen <ip:port>] [--trap-sink <ip:port>]

Other commands:
  snmp-proxy genpsk     print a fresh random pre-shared key (hex)
  snmp-proxy version

The manager instance listens for clear SNMP from managers and dials the
secured tunnel; the agent instance listens on the tunnel and forwards to
the real SNMP agent. Run one instance on each side of the secured line.
Both sides must share the same --psk, --auth-pass and --priv-pass.
`)
}
