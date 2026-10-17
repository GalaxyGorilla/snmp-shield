// Package proxy wires the config, tunnel session, and passthrough
// forwarders into a runnable proxy for each role, with graceful
// shutdown and metrics serving.
package proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kattelma/snmp-proxy/internal/cache"
	"github.com/kattelma/snmp-proxy/internal/config"
	"github.com/kattelma/snmp-proxy/internal/observ"
	"github.com/kattelma/snmp-proxy/internal/passthrough"
	"github.com/kattelma/snmp-proxy/internal/tunnel"
	"github.com/kattelma/snmp-proxy/internal/usm"
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

	switch opts.Config.Security.Mode {
	case "usm-translate":
		return runManagerUSM(ctx, opts, met, sess)
	default:
		mgr := passthrough.NewManager(opts.Config.Manager, sess, opts.Log, met)
		return mgr.Run(ctx)
	}
}

// runManagerUSM wires the USM translate manager-side engine.
func runManagerUSM(ctx context.Context, opts Options, met *observ.Metrics, sess *tunnel.Session) error {
	store, err := cache.Open(opts.Config.Security.EngineStore)
	if err != nil {
		return err
	}
	engineID, err := parseEngineID(opts.Config.Security.EngineID)
	if err != nil {
		return err
	}
	clock, err := cache.NewEngineClock(store, engineID, zapLogger{opts.Log})
	if err != nil {
		return err
	}
	tr, terr := usm.NewManagerTranslator(opts.Config.Manager, opts.Config.Security, clock, sess, opts.Log, met)
	if terr != nil {
		return terr
	}
	return tr.Run(ctx.Done())
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

	// Unblock Accept on shutdown.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-done:
		}
	}()

	// USM mode state is per-instance (one authoritative engine shared by
	// all tunnel sessions).
	usmMode := opts.Config.Security.Mode == "usm-translate"
	var clock *cache.EngineClock
	if usmMode {
		store, err := cache.Open(opts.Config.Security.EngineStore)
		if err != nil {
			return err
		}
		engineID, err := parseEngineID(opts.Config.Security.EngineID)
		if err != nil {
			return err
		}
		clock, err = cache.NewEngineClock(store, engineID, zapLogger{opts.Log})
		if err != nil {
			return err
		}
	}

	// Serve tunnel sessions concurrently: every manager-side proxy dials
	// its own session, and each is served in parallel. Requests within a
	// session are multiplexed by frame correlation id.
	var wg sync.WaitGroup
	for {
		conn, aerr := l.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("tunnel accept: %w", aerr)
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			sess := tunnel.NewServerSession(conn, opts.Config.Tunnel.MaxFrameSize, 1200, opts.Log)
			defer sess.Close()
			var rerr error
			if usmMode {
				var tr *usm.AgentTranslator
				tr, rerr = usm.NewAgentTranslator(opts.Config.Agent, usm.ProfilesFromSecurity(opts.Config.Security), clock, sess, opts.Log, met)
				if rerr == nil {
					rerr = tr.Run(ctx.Done())
				}
			} else {
				agt := passthrough.NewAgent(opts.Config.Agent, sess, opts.Log, met)
				rerr = agt.Run(ctx)
			}
			if rerr != nil {
				opts.Log.Error("agent session ended", zap.Error(rerr))
			}
		}(conn)
	}
	wg.Wait()
	return nil
}

// parseEngineID parses a config engine ID: "hex:..." or bare hex.
func parseEngineID(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	s = strings.TrimPrefix(s, "hex:")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("security.engine_id: %w", err)
	}
	return b, nil
}

// zapLogger adapts *zap.Logger to the cache.Logger interface.
type zapLogger struct{ l *zap.Logger }

func (z zapLogger) Logf(format string, args ...any) {
	z.l.Info(fmt.Sprintf(format, args...))
}