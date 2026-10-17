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

	"github.com/GalaxyGorilla/snmp-proxy/internal/cache"
	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/passthrough"
	"github.com/GalaxyGorilla/snmp-proxy/internal/snmpmetrics"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tsm"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
	"github.com/GalaxyGorilla/snmp-proxy/internal/usm"
	"go.uber.org/zap"
)

// Options for a proxy run.
type Options struct {
	Config      *config.Config
	MetricsAddr string
	Log         *zap.Logger
	// Version is the product version string surfaced in the SNMP health
	// MIB (defaults to "dev" when empty).
	Version string
}

// SNMP event trap OIDs, relative to the metrics base (base + ".2.x").
const (
	trapTunnelUpOID   = ".2.1"
	trapTunnelDownOID = ".2.2"
	trapFailoverOID   = ".2.3"
)

// newSNMPMetricsAgent builds the optional SNMP health agent from the
// metrics config. Returns nil when neither the MIB listener nor a trap
// sink is configured.
func newSNMPMetricsAgent(opts Options, met *observ.Metrics) *snmpmetrics.Agent {
	m := opts.Config.Metrics
	if m.ListenAddr == "" && m.TrapSinkAddr == "" {
		return nil
	}
	ver := opts.Version
	if ver == "" {
		ver = "dev"
	}
	return snmpmetrics.New(snmpmetrics.Config{
		Community:  m.Community,
		BaseOID:    m.BaseOID,
		Version:    ver,
		Role:       string(opts.Config.Role),
		SecMode:    opts.Config.Security.Mode,
		TunnelMode: opts.Config.Tunnel.Mode,
		Endpoints:  strings.Join(opts.Config.DialEndpoints(), ","),
	}, met.CounterList(), met.ForwardLatency, opts.Log)
}

// serveSNMPMetrics runs the SNMP MIB listener until stop is closed.
func serveSNMPMetrics(agent *snmpmetrics.Agent, opts Options, stop <-chan struct{}) {
	if agent == nil || opts.Config.Metrics.ListenAddr == "" {
		return
	}
	go func() {
		if err := agent.Serve(opts.Config.Metrics.ListenAddr, stop); err != nil {
			opts.Log.Error("snmp metrics agent", zap.Error(err))
		}
	}()
}

// installTunnelEvents hooks tunnel lifecycle events into the SNMP
// metrics agent: scalars (tunnelUp/endpoint) update on every event and
// a v2c trap goes to Metrics.TrapSinkAddr when one is configured. Safe
// to call with a nil agent.
func installTunnelEvents(sess *tunnel.Session, agent *snmpmetrics.Agent, opts Options) {
	if agent == nil || sess == nil {
		return
	}
	m := opts.Config.Metrics
	var sink net.Addr
	if m.TrapSinkAddr != "" {
		if addr, err := net.ResolveUDPAddr("udp", m.TrapSinkAddr); err == nil {
			sink = addr
		} else {
			opts.Log.Warn("snmp metrics trap sink unresolvable", zap.Error(err))
		}
	}
	sess.SetEventFunc(func(ev tunnel.Event) {
		up := ev.Kind == tunnel.EventTunnelUp
		failedOver := ev.Kind == tunnel.EventFailover
		agent.SetTunnelUp(up, ev.Endpoint)
		if sink == nil {
			return
		}
		oid := trapTunnelUpOID
		switch ev.Kind {
		case tunnel.EventTunnelUp:
			if failedOver {
				oid = trapFailoverOID
			}
		case tunnel.EventFailover:
			oid = trapFailoverOID
		case tunnel.EventTunnelDown:
			oid = trapTunnelDownOID
		}
		// BaseOID arrives dotted with a leading dot from config; the
		// trap OID is relative and also dotted — join without doubling.
		base := strings.TrimSuffix(strings.TrimPrefix(m.BaseOID, "."), ".")
		if base == "" {
			base = "1.3.6.1.4.1.58427.1"
		}
		trapOID := base + "." + strings.TrimPrefix(oid, ".")
		if err := agent.SendTrap(trapOID, sink); err != nil && opts.Log != nil {
			opts.Log.Debug("snmp metrics trap", zap.Error(err))
		}
	})
}

// Run executes the configured role until SIGINT/SIGTERM.
func Run(opts Options) error {
	met := observ.NewMetrics()
	var metSrv *http.Server
	if opts.MetricsAddr != "" {
		metSrv = observ.ServeMetrics(opts.MetricsAddr, met.Handler(), opts.Log)
		defer observ.ShutdownMetrics(metSrv)
	}

	// Optional SNMP health MIB + event traps (all roles).
	snmpAgent := newSNMPMetricsAgent(opts, met)
	snmpStop := make(chan struct{})
	defer close(snmpStop)
	serveSNMPMetrics(snmpAgent, opts, snmpStop)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch opts.Config.Role {
	case config.RoleManager:
		return runManager(ctx, opts, met, snmpAgent)
	case config.RoleAgent:
		return runAgent(ctx, opts, met, snmpAgent)
	case config.RoleGateway:
		return runGateway(ctx, opts, met)
	default:
		return fmt.Errorf("unknown role %q", opts.Config.Role)
	}
}

// runManager runs the manager-side instance: it dials the tunnel and
// serves the clear manager leg.
func runManager(ctx context.Context, opts Options, met *observ.Metrics, snmpAgent *snmpmetrics.Agent) error {
	psk, err := opts.Config.PSKBytes()
	if err != nil {
		return err
	}
	addrs := opts.Config.DialEndpoints()
	dial := &tunnel.Dialer{
		Mode:            opts.Config.Tunnel.Mode,
		RemoteAddr:      addrs[0],
		RemoteAddrs:     addrs,
		PSK:             psk,
		PSKIdentity:     []byte(opts.Config.Tunnel.PSKIdentity),
		PskCiphersuites: opts.Config.Tunnel.PskCiphersuites,
		CAFile:          opts.Config.Tunnel.CAFile,
		CertFile:        opts.Config.Tunnel.CertFile,
		KeyFile:         opts.Config.Tunnel.KeyFile,
		ServerName:      opts.Config.Tunnel.ServerName,
		Insecure:        opts.Config.Tunnel.InsecureSkipVerify,
		Timeout:         10 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, opts.Config.Tunnel.MaxFrameSize, 1200, opts.Log)
	defer sess.Close()
	sess.SetMetrics(met)
	sess.SetTuning(opts.Config.Keepalive(), opts.Config.Backoff())

	// Connect eagerly: the first Send on a lazy session races the DTLS
	// handshake and the first app record can be lost (pion's server-side
	// handshake only starts once the client writes).
	if err := sess.Connect(ctx); err != nil {
		opts.Log.Warn("tunnel initial connect failed; will retry in background", zap.Error(err))
	}
	installTunnelEvents(sess, snmpAgent, opts)

	switch opts.Config.Security.Mode {
	case "usm-translate":
		return runManagerUSM(ctx, opts, met, sess)
	case "tsm":
		filt, ferr := opts.Config.TrapFilter()
		if ferr != nil {
			return ferr
		}
		tr, err := tsm.NewManagerTranslator(opts.Config.Manager, opts.Config.Security, sess, opts.Log, met, filt)
		if err != nil {
			return err
		}
		return tr.Run(ctx.Done())
	default:
		filt, ferr := opts.Config.TrapFilter()
		if ferr != nil {
			return ferr
		}
		mgr := passthrough.NewManager(opts.Config.Manager, sess, opts.Log, met, filt)
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
	filt, ferr := opts.Config.TrapFilter()
	if ferr != nil {
		return ferr
	}
	tr, terr := usm.NewManagerTranslator(opts.Config.Manager, opts.Config.Security, clock, sess, opts.Log, met, filt)
	if terr != nil {
		return terr
	}
	return tr.Run(ctx.Done())
}

// runAgent runs the agent-side instance: it listens on the tunnel and
// serves the clear agent leg.
func runAgent(ctx context.Context, opts Options, met *observ.Metrics, snmpAgent *snmpmetrics.Agent) error {
	psk, err := opts.Config.PSKBytes()
	if err != nil {
		return err
	}
	lcfg := tunnel.ListenerConfig{
		Mode:            opts.Config.Tunnel.Mode,
		PSK:             psk,
		PSKIdentity:     []byte(opts.Config.Tunnel.PSKIdentity),
		PskCiphersuites: opts.Config.Tunnel.PskCiphersuites,
		CAFile:          opts.Config.Tunnel.CAFile,
		CertFile:        opts.Config.Tunnel.CertFile,
		KeyFile:         opts.Config.Tunnel.KeyFile,
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
	tsmMode := opts.Config.Security.Mode == "tsm"
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
			// Cancel per-session work when the tunnel conn dies (the
			// server readLoop fires Done); otherwise the translator
			// leaks per reconnect.
			sctx, scancel := context.WithCancel(ctx)
			defer scancel()
			go func() {
				select {
				case <-sess.Done():
					scancel()
				case <-ctx.Done():
				}
				scancel()
			}()
			sess.SetTuning(opts.Config.Keepalive(), 0)
			installTunnelEvents(sess, snmpAgent, opts)
			var rerr error
			if usmMode {
				var tr *usm.AgentTranslator
				tr, rerr = usm.NewAgentTranslator(opts.Config.Agent, usm.ProfilesFromSecurity(opts.Config.Security), clock, sess, opts.Log, met)
				if rerr == nil {
					rerr = tr.Run(sctx.Done())
				}
			} else if tsmMode {
				var tr *tsm.AgentTranslator
				tr, rerr = tsm.NewAgentTranslator(opts.Config.Agent, opts.Config.Security, sess, opts.Log, met)
				if rerr == nil {
					rerr = tr.Run(sctx.Done())
				}
			} else {
				filt, ferr := opts.Config.TrapFilter()
				if ferr != nil {
					opts.Log.Error("notification filter", zap.Error(ferr))
					return
				}
				agt := passthrough.NewAgent(opts.Config.Agent, sess, opts.Log, met, filt)
				rerr = agt.Run(sctx)
			}
			if rerr != nil {
				opts.Log.Error("agent session ended", zap.Error(rerr))
			}
		}(conn)
	}
	wg.Wait()
	return nil
}

// runGateway runs the single-box gateway: the front leg terminates SNMP
// security directly from third-party clients and authenticated requests
// are relayed as clear v1/v2c to the legacy agent. No tunnel, no second
// proxy.
//
//   - usm-gateway: plain-UDP front leg terminating SNMPv3 USM (this
//     instance is the authoritative engine).
//   - tsm-gateway: raw DTLS front leg (RFC 6353, one SNMP datagram per
//     DTLS record, no frame layer); the handshake is the authentication.
func runGateway(ctx context.Context, opts Options, met *observ.Metrics) error {
	filt, ferr := opts.Config.TrapFilter()
	if ferr != nil {
		return ferr
	}
	switch opts.Config.Security.Mode {
	case "tsm-gateway":
		lcfg := tunnel.ListenerConfig{
			Mode:     "dtls",
			CAFile:   opts.Config.Tunnel.CAFile,
			CertFile: opts.Config.Tunnel.CertFile,
			KeyFile:  opts.Config.Tunnel.KeyFile,
			Insecure: opts.Config.Tunnel.InsecureSkipVerify,
		}
		gw, err := tsm.NewTSMGateway(opts.Config.Gateway, opts.Config.Security, lcfg, opts.Log, met, filt)
		if err != nil {
			return err
		}
		return gw.Run(ctx.Done())
	case "usm-manager":
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
		users := usm.ProfilesFromSecurity(opts.Config.Security)
		if len(users) == 0 {
			return fmt.Errorf("security.users: usm-manager needs at least one user")
		}
		mg, err := usm.NewManagerGateway(opts.Config.Gateway, users, clock, opts.Log, met, filt)
		if err != nil {
			return err
		}
		return mg.Run(ctx.Done())
	default:
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
		users := usm.ProfilesFromSecurity(opts.Config.Security)
		if len(users) == 0 {
			return fmt.Errorf("security.users: usm-gateway needs at least one user")
		}
		tr, terr := usm.NewGatewayTranslator(opts.Config.Gateway, users, clock, opts.Log, met, filt)
		if terr != nil {
			return terr
		}
		return tr.Run(ctx.Done())
	}
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
