// Command snmp-proxy runs one instance of the SNMP securing proxy.
// The role is chosen by subcommand: manager or agent.
package main

import (
	"fmt"
	"os"

	"github.com/kattelma/snmp-proxy/internal/config"
	"github.com/kattelma/snmp-proxy/internal/observ"
	"github.com/kattelma/snmp-proxy/internal/proxy"
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
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

func runRole(role string, args []string) int {
	fs := pflag.NewFlagSet(role, pflag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to YAML config file (required)")
	metricsAddr := fs.String("metrics-addr", "", "Prometheus metrics listen address (e.g. 127.0.0.1:9672)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, error")
	dev := fs.Bool("dev", false, "development logging (console output)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
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
	cfg, err := config.Load(*cfgPath, r)
	if err != nil {
		log.Error("load config", zap.Error(err))
		return 1
	}

	log.Info("starting snmp-proxy",
		zap.String("role", role),
		zap.String("tunnel_mode", cfg.Tunnel.Mode),
		zap.String("config", *cfgPath))

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

func usage(w *os.File) {
	fmt.Fprintf(w, `snmp-proxy — SNMP securing proxy

Usage:
  snmp-proxy manager --config <file> [--metrics-addr <addr>]
  snmp-proxy agent   --config <file> [--metrics-addr <addr>]
  snmp-proxy version

The manager instance listens for clear SNMP from managers and dials the
secured tunnel; the agent instance listens on the tunnel and forwards to
the real SNMP agent. Run one instance on each side of the secured line.
`)
}
