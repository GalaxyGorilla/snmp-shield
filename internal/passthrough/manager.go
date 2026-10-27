package passthrough

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// Manager-side forwarding: clear UDP listener (managers connect here) ->
// tunnel REQ frames; tunnel RESP frames -> the originating manager.
// Device notifications arriving over the tunnel are delivered to the
// configured trap sink. Local devices may also send notifications to
// TrapListenAddr; those ship across the tunnel.
type Manager struct {
	cfg   config.ManagerRole
	sess  *tunnel.Session
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)
	// access is the clear-leg policy (client allow-list, rate limit,
	// write policy); nil holder / nil policy = allow everything.
	access *access.Holder

	conn     *net.UDPConn // clear request listener
	trapConn *net.UDPConn // optional clear trap listener
	sink     *net.UDPConn // sink socket for delivering tunnel notifications

	pendMu sync.Mutex
	pend   map[uint16]*pending // corrID -> pending request
	nextID atomic.Uint32

	socksMu    sync.Mutex // guards conn/trapConn/sink vs Close
	baseCtx    context.Context
	baseCancel context.CancelFunc

	stop chan struct{}
}

// pending tracks one manager request awaiting its response.
type pending struct {
	addr  *net.UDPAddr
	ready chan struct{}
	resp  []byte
}

// NewManager creates the manager-side forwarder.
func NewManager(cfg config.ManagerRole, sess *tunnel.Session, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) *Manager {
	return &Manager{
		cfg:   cfg,
		sess:  sess,
		log:   log,
		met:   met,
		filtr: notifyfilter.From(filt...),
		pend:  make(map[uint16]*pending),
		stop:  make(chan struct{}),
	}
}

// SetAccess installs (or replaces) the clear-leg access policy. The policy
// is read per datagram, so a reload takes effect on the next request.
func (m *Manager) SetAccess(h *access.Holder) { m.access = h }

// Run starts the manager-side forwarder. It blocks until ctx is
// cancelled or a fatal error occurs.
func (m *Manager) Run(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", m.cfg.ListenAddr, err)
	}
	m.socksMu.Lock()
	m.conn = conn
	m.socksMu.Unlock()
	defer func() {
		m.socksMu.Lock()
		m.conn = nil
		m.socksMu.Unlock()
		conn.Close()
	}()

	if m.cfg.TrapSinkAddr != "" {
		saddr, rerr := net.ResolveUDPAddr("udp", m.cfg.TrapSinkAddr)
		if rerr == nil {
			s, derr := net.DialUDP("udp", nil, saddr)
			if derr != nil {
				m.log.Warn("trap sink unreachable at startup",
					zap.String("sink", m.cfg.TrapSinkAddr), zap.Error(derr))
			} else {
				m.socksMu.Lock()
				m.sink = s
				m.socksMu.Unlock()
			}
		} else {
			m.log.Warn("cannot resolve trap sink", zap.String("sink", m.cfg.TrapSinkAddr), zap.Error(rerr))
		}
	}
	var trapConn *net.UDPConn
	if m.cfg.TrapListenAddr != "" {
		taddr, rerr := net.ResolveUDPAddr("udp", m.cfg.TrapListenAddr)
		if rerr != nil {
			return fmt.Errorf("resolve trap listen addr: %w", rerr)
		}
		trapConn, err = net.ListenUDP("udp", taddr)
		if err != nil {
			return fmt.Errorf("listen trap udp %s: %w", m.cfg.TrapListenAddr, err)
		}
		m.socksMu.Lock()
		m.trapConn = trapConn
		m.socksMu.Unlock()
		defer func() {
			m.socksMu.Lock()
			m.trapConn = nil
			m.socksMu.Unlock()
			trapConn.Close()
		}()
	}

	respCh, cancelResp := m.sess.Subscribe(tunnel.TypeRESP)
	notifCh, cancelNotif := m.sess.Subscribe(tunnel.TypeNOTIF)
	defer cancelResp()
	defer cancelNotif()

	go m.sinkLoop(notifCh)
	go m.respLoop(respCh)

	errCh := make(chan error, 2)
	go func() { errCh <- m.serveClearRequests() }()
	if m.trapConn != nil {
		go func() { errCh <- m.serveClearTraps() }()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// Close releases resources.
func (m *Manager) Close() {
	close(m.stop)
	m.socksMu.Lock()
	conn, trapConn, sink := m.conn, m.trapConn, m.sink
	m.socksMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if trapConn != nil {
		_ = trapConn.Close()
	}
	if sink != nil {
		_ = sink.Close()
	}
}

// serveClearRequests reads clear SNMP requests from managers and ships
// them as tunnel REQ frames with a fresh corrID.
func (m *Manager) serveClearRequests() error {
	buf := make([]byte, 65536)
	for {
		m.socksMu.Lock()
		conn := m.conn
		m.socksMu.Unlock()
		if conn == nil {
			return fmt.Errorf("clear read: socket closed")
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.stop:
				return nil
			default:
			}
			return fmt.Errorf("clear read: %w", err)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])

		// Access policy on the clear manager leg. Off-list and over-rate
		// clients are dropped in silence; a write refusal is answered so
		// the manager learns immediately.
		pol := m.access.Get()
		switch pol.Check(access.IPOf(addr)) {
		case access.DeniedClient:
			if m.met != nil {
				m.met.ACLDenied.Inc()
			}
			continue
		case access.DeniedRate:
			if m.met != nil {
				m.met.RateLimited.Inc()
			}
			continue
		}
		// The write policy only sees v1/v2c: passthrough forwards v3
		// opaquely, so a v3 SET cannot be inspected (inherent to
		// passthrough, not a gap here).
		if ver, community, pdu, serr := msg.SplitV1V2c(payload); serr == nil {
			if !pol.AllowWrite(pdu) {
				if m.met != nil {
					m.met.WritesDenied.Inc()
				}
				if out, ok := access.DenyResponse(ver, community, pdu); ok {
					if _, werr := conn.WriteToUDP(out, addr); werr != nil && m.log != nil {
						m.log.Debug("notWritable delivery failed", zap.Error(werr))
					}
				}
				continue
			}
		}

		corrID := uint16(m.nextID.Add(1))
		p := &pending{addr: addr, ready: make(chan struct{})}
		m.pendMu.Lock()
		m.pend[corrID] = p
		m.pendMu.Unlock()

		if m.met != nil {
			m.met.ReqForwarded.Inc()
			m.met.BytesSent.Add(float64(len(payload)))
		}
		if err := m.sess.Send(m.reqCtx(), tunnel.TypeREQ, 0, corrID, payload); err != nil {
			m.pendMu.Lock()
			delete(m.pend, corrID)
			m.pendMu.Unlock()
			if m.met != nil {
				m.met.ReqErrors.Inc()
			}
			m.log.Warn("tunnel send failed", zap.Error(err))
			continue // manager will retransmit
		}

		// Wait for the response and deliver it; SNMP managers retransmit
		// on their own, but we must not leak pending entries.
		go m.awaitResponse(corrID, p)
	}
}

// awaitResponse waits for p's response and delivers it to the manager.
func (m *Manager) awaitResponse(corrID uint16, p *pending) {
	select {
	case <-p.ready:
		m.socksMu.Lock()
		conn := m.conn
		m.socksMu.Unlock()
		if conn != nil {
			if _, err := conn.WriteToUDP(p.resp, p.addr); err != nil && m.log != nil {
				m.log.Warn("deliver response", zap.Error(err))
			}
		}
	case <-time.After(15 * time.Second):
	case <-m.stop:
	}
	m.pendMu.Lock()
	delete(m.pend, corrID)
	m.pendMu.Unlock()
}

// respLoop delivers tunnel RESP frames to the pending request map.
func (m *Manager) respLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		m.pendMu.Lock()
		if p, ok := m.pend[f.CorrID]; ok && p.resp == nil {
			p.resp = append([]byte(nil), f.Payload...)
			close(p.ready)
		}
		m.pendMu.Unlock()
	}
}

// sinkLoop delivers tunnel NOTIF frames (device notifications) to the
// configured trap sink.
func (m *Manager) sinkLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		m.met.NotifsRelayed.Inc()
		if m.sink == nil {
			if m.cfg.TrapSinkAddr == "" {
				continue
			}
			saddr, err := net.ResolveUDPAddr("udp", m.cfg.TrapSinkAddr)
			if err != nil {
				continue
			}
			s, derr := net.DialUDP("udp", nil, saddr)
			if derr != nil {
				if m.log != nil {
					m.log.Warn("trap sink dial", zap.Error(derr))
				}
				continue
			}
			m.sink = s
		}
		if _, err := m.sink.Write(f.Payload); err != nil && m.log != nil {
			m.log.Warn("trap sink write", zap.Error(err))
		}
	}
}

// serveClearTraps reads notifications from local devices and ships them
// across the tunnel as NOTIF frames.
func (m *Manager) serveClearTraps() error {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := m.trapConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.stop:
				return nil
			default:
			}
			return fmt.Errorf("trap read: %w", err)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])

		if m.filtr != nil {
			if info, perr := msg.Peek(payload); perr == nil && (msg.IsTrap(info.PDUType) || msg.IsInform(info.PDUType)) {
				oid, ok := msg.TrapOID(payload)
				if !ok || !m.filtr.Allowed(oid) {
					if m.met != nil {
						m.met.NotifsFiltered.Inc()
					}
					m.log.Debug("notification filtered",
						zap.String("trap_oid", oid), zap.String("addr", raddr.String()))
					continue
				}
			}
		}

		corrID := uint16(m.nextID.Add(1))
		if m.met != nil {
			m.met.NotifsRelayed.Inc()
		}
		if err := m.sess.Send(m.trapCtx(), tunnel.TypeNOTIF, 0, corrID, payload); err != nil {
			if m.met != nil {
				m.met.DropTotal.Inc()
			}
		}
	}
}

// ctxPair builds a context cancelled when the manager stops.
func (m *Manager) ctxPair() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-m.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (m *Manager) reqCtx() context.Context {
	// One shared context per call would leak goroutines; use a single
	// long-lived context tied to stop instead.
	if m.baseCtx == nil {
		ctx, cancel := m.ctxPair()
		m.baseCtx = ctx
		m.baseCancel = cancel
	}
	return m.baseCtx
}

func (m *Manager) trapCtx() context.Context {
	return m.reqCtx()
}
