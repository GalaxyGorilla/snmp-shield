// Package proxy wires the config, tunnel session, and passthrough
// forwarders into a runnable proxy for each role, with graceful
// shutdown and metrics serving.
package proxy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kattelma/snmp-proxy/internal/config"
	"github.com/kattelma/snmp-proxy/internal/observ"
	"github.com/kattelma/snmp-proxy/internal/passthrough"
	"github.com/kattelma/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// Options for a proxy run.
type Options struct {
	Config     *config.Config
	MetricsAddr string
	Log        *zap.Logger
}

// Run executes the configured role until SIGINT/SIGTERM.
func Run(opts Options) error {
	met := observ.NewMetrics()
	var metSrv *http.Server
	if opts.MetricsAddr != "" {
		metSrv = observ.ServeMetrics(opts.MetricsAddr, met.Handler(), opts.Log)
		defer observ.ShutdownMetrics(metSrv)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch opts.Config.Role {
	case config.RoleManager:
		return runManager(ctx, opts, met)
	case config.RoleAgent:
		return runAgent(ctx, opts, met)
	default:
		return fmt.Errorf("unknown role %q", opts.Config.Role)
	}
}

// runManager runs the manager-side instance: it dials the tunnel and
// serves the clear manager leg.
func runManager(ctx context.Context, opts Options, met *observ.Metrics) error {
	psk, err := opts.Config.PSKBytes()
	if err != nil {
		return err
	}
	dial := &tunnel.Dialer{
		Mode:        opts.Config.Tunnel.Mode,
		RemoteAddr:  opts.Config.Tunnel.DialAddr,
		PSK:         psk,
		PSKIdentity: []byte(opts.Config.Tunnel.PSKIdentity),
		CAFile:      opts.Config.Tunnel.CAFile,
		CertFile:    opts.Config.Tunnel.CertFile,
		KeyFile:     opts.Config.Tunnel.KeyFile,
		ServerName:  opts.Config.Tunnel.ServerName,
		Insecure:    opts.Config.Tunnel.InsecureSkipVerify,
		Timeout:     10 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, opts.Config.Tunnel.MaxFrameSize, 1200, opts.Log)
	defer sess.Close()

	mgr := passthrough.NewManager(opts.Config.Manager, sess, opts.Log, met)
	return mgr.Run(ctx)
}

// runAgent runs the agent-side instance: it listens on the tunnel and
// serves the clear agent leg.
func runAgent(ctx context.Context, opts Options, met *observ.Metrics) error {
	psk, err := opts.Config.PSKBytes()
	if err != nil {
		return err
	}
	lcfg := tunnel.ListenerConfig{
		Mode:        opts.Config.Tunnel.Mode,
		PSK:         psk,
		PSKIdentity: []byte(opts.Config.Tunnel.PSKIdentity),
		CAFile:      opts.Config.Tunnel.CAFile,
		CertFile:    opts.Config.Tunnel.CertFile,
		KeyFile:     opts.Config.Tunnel.KeyFile,
	}
	l, err := tunnel.Listen(opts.Config.Tunnel.ListenAddr, lcfg)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	defer l.Close()

	// Accept one tunnel session at a time; the agent side serves the
	// single upstream agent per config.
	for {
		conn, aerr := l.Accept()
		if aerr != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return fmt.Errorf("tunnel accept: %w", aerr)
		}
		sess := tunnel.NewServerSession(conn, opts.Config.Tunnel.MaxFrameSize, 1200, opts.Log)
		agt := passthrough.NewAgent(opts.Config.Agent, sess, opts.Log, met)
		aerr = agt.Run(ctx)
		_ = sess.Close()
		if aerr != nil {
			opts.Log.Error("agent session ended", zap.Error(aerr))
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}