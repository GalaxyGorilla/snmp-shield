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
	"github.com/GalaxyGorilla/snmp-shield/internal/safego"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// Manager-side forwarding: clear UDP listener (managers connect here) ->
// tunnel REQ frames; tunnel RESP frames -> the originating manager.
// Device notifications arriving over the tunnel are delivered to the
// configured trap sink. Local devices may also send notifications to
// TrapListenAddr; those ship across the tunnel and are delivered at the
// agent side's trap sink, with informs confirmed back to the device.
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

	informMu sync.Mutex
	inform   map[uint16]*informPend // corrID -> inform awaiting confirmation

	socksMu    sync.Mutex // guards conn/trapConn/sink vs Close
	baseOnce   sync.Once  // guards the lazy send context
	jobCtx     context.Context
	baseCancel context.CancelFunc

	stop chan struct{}
}

// pending tracks one manager request awaiting its response.
type pending struct {
	addr  *net.UDPAddr
	ready chan struct{}
	resp  []byte
}

// informPend tracks one inform in flight between the two proxies: registered on
// whichever side accepted it from the device, released by the confirmation
// that comes back over the tunnel. It carries what the device's confirmation
// has to echo — request-id, version, community and the request's varbinds
// (RFC 3416 §4.2.1: a Response repeats them) — and where to send it.
//
// `ready` is the agent side's completion signal: it is closed when the
// confirmation arrives, which releases the 15s timeout wait instead of
// leaving it to expire (the soak work removed exactly that shape of
// rate × timeout goroutine).
type informPend struct {
	addr      *net.UDPAddr
	ver       int
	community []byte
	reqID     int32
	varbinds  []byte
	ready     chan struct{}
}

// NewManager creates the manager-side forwarder.
func NewManager(cfg config.ManagerRole, sess *tunnel.Session, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) *Manager {
	return &Manager{
		cfg:    cfg,
		sess:   sess,
		log:    log,
		met:    met,
		filtr:  notifyfilter.From(filt...),
		pend:   make(map[uint16]*pending),
		inform: make(map[uint16]*informPend),
		stop:   make(chan struct{}),
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
	if trapConn != nil {
		// Pass the local: m.trapConn is cleared under socksMu when Run
		// returns, and a serve loop that re-read the field raced that write.
		go func() { errCh <- m.serveClearTraps(trapConn) }()
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
		safego.Dispatch(m.log, "passthrough manager request", func() { m.handleClearRequest(conn, payload, addr) })
	}
}

// handleClearRequest applies the access policy to one clear request and
// ships it over the tunnel. It runs under safego.Dispatch: the datagram is
// untrusted input.
func (m *Manager) handleClearRequest(conn *net.UDPConn, payload []byte, addr *net.UDPAddr) {
	// Access policy on the clear manager leg. Off-list and over-rate
	// clients are dropped in silence; a write refusal is answered so
	// the manager learns immediately.
	pol := m.access.Get()
	switch pol.Check(access.IPOf(addr)) {
	case access.DeniedClient:
		if m.met != nil {
			m.met.ACLDenied.Inc()
		}
		return
	case access.DeniedRate:
		if m.met != nil {
			m.met.RateLimited.Inc()
		}
		return
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
			return
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
		return // manager will retransmit
	}

	// Wait for the response and deliver it; SNMP managers retransmit
	// on their own, but we must not leak pending entries.
	go m.awaitResponse(corrID, p)
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

// respLoop delivers tunnel RESP frames to the pending request map, and
// inform confirmations to the device that sent the inform.
func (m *Manager) respLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		if f.Flags&tunnel.FlagInform != 0 {
			m.handleInformResp(f)
			continue
		}
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
		if m.met != nil {
			m.met.NotifsRelayed.Inc()
		}
		m.socksMu.Lock()
		sink := m.sink
		m.socksMu.Unlock()
		if sink == nil {
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
			m.socksMu.Lock()
			m.sink = s
			m.socksMu.Unlock()
			sink = s
		}
		_, werr := sink.Write(f.Payload)
		if werr != nil && m.log != nil {
			m.log.Warn("trap sink write", zap.Error(werr))
		}
		// An inform is confirmed only after the sink accepted it: the agent
		// side waits for this frame and relays it to the device, and a
		// confirmation for a notification that was never delivered would be
		// a lie the device cannot detect.
		if f.Flags&tunnel.FlagInform != 0 && werr == nil {
			if serr := m.sess.Send(m.trapCtx(), tunnel.TypeRESP, tunnel.FlagInform, f.CorrID, nil); serr != nil && m.log != nil {
				m.log.Warn("send inform confirmation", zap.Error(serr))
			}
		}
	}
}

// serveClearTraps reads notifications from local devices and ships them
// across the tunnel as NOTIF frames.
func (m *Manager) serveClearTraps(conn *net.UDPConn) error {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
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
		safego.Dispatch(m.log, "passthrough manager trap", func() { m.handleClearTrap(payload, raddr) })
	}
}

// handleClearTrap ships one clear notification from a local device over
// the tunnel toward the manager side.
func (m *Manager) handleClearTrap(payload []byte, raddr *net.UDPAddr) {
	info, perr := msg.Peek(payload)
	if perr != nil || !(msg.IsTrap(info.PDUType) || msg.IsInform(info.PDUType)) {
		// Same ingress rule as the agent side: a notification port carries
		// notifications. Without this, a port probe or a misdirected request
		// would be forwarded over the tunnel and delivered to the sink as if
		// the device had sent it.
		if m.met != nil {
			m.met.DropTotal.Inc()
		}
		if m.log != nil {
			m.log.Debug("notification ingress: not a notification; dropped",
				zap.Int("bytes", len(payload)), zap.String("addr", raddr.String()))
		}
		return
	}
	isInform := msg.IsInform(info.PDUType)
	if m.filtr != nil {
		oid, ok := msg.TrapOID(payload)
		if !ok || !m.filtr.Allowed(oid) {
			if m.met != nil {
				m.met.NotifsFiltered.Inc()
			}
			m.log.Debug("notification filtered",
				zap.String("trap_oid", oid), zap.String("addr", raddr.String()))
			return
		}
	}

	corrID := uint16(m.nextID.Add(1))
	if isInform {
		// Remember what the device's confirmation must echo. Registration
		// requires the parse to succeed: a confirmation built from zero
		// values would be worse than none, because the device would accept
		// it as its answer.
		if p, ok := parseInformPend(payload, raddr); ok {
			m.informMu.Lock()
			m.inform[corrID] = p
			m.informMu.Unlock()
			go m.awaitInform(corrID)
		} else if m.log != nil {
			m.log.Warn("inform from a device is undecodable; forwarding it but it cannot be confirmed",
				zap.String("addr", raddr.String()))
		}
	}
	if m.met != nil {
		m.met.NotifsRelayed.Inc()
	}
	flags := uint8(0)
	if isInform {
		flags = tunnel.FlagInform
	}
	if err := m.sess.Send(m.trapCtx(), tunnel.TypeNOTIF, flags, corrID, payload); err != nil {
		if m.met != nil {
			m.met.DropTotal.Inc()
		}
		if isInform {
			m.informMu.Lock()
			delete(m.inform, corrID)
			m.informMu.Unlock()
		}
	}
}

// parseInformPend captures the fields a device's confirmation has to echo.
func parseInformPend(payload []byte, raddr *net.UDPAddr) (*informPend, bool) {
	ver, comm, pdu, err := msg.SplitV1V2c(payload)
	if err != nil {
		return nil, false
	}
	typ, f, err := msg.ParsePDU(pdu)
	if err != nil || !msg.IsInform(typ) {
		return nil, false
	}
	return &informPend{addr: raddr, ver: ver, community: comm, reqID: f.ReqID, varbinds: f.Varbinds}, true
}

// awaitInform drops an inform pending entry that was never confirmed, so a
// dead tunnel or a vanished sink cannot grow the map.
func (m *Manager) awaitInform(corrID uint16) {
	select {
	case <-time.After(15 * time.Second):
	case <-m.stop:
	}
	m.informMu.Lock()
	delete(m.inform, corrID)
	m.informMu.Unlock()
}

// handleInformResp turns an agent-side confirmation into the clear GetResponse
// the device expects, and sends it FROM the socket that received the inform.
//
// Both halves matter: an unconfirmed inform is retransmitted until the device
// gives up, and a connected UDP sender (gosnmp, net-snmp's default) drops an
// answer that arrives from a different source port.
func (m *Manager) handleInformResp(f *tunnel.Frame) {
	m.informMu.Lock()
	p := m.inform[f.CorrID]
	delete(m.inform, f.CorrID)
	m.informMu.Unlock()
	if p == nil {
		return // already timed out, or not ours
	}
	resp := msg.BuildPDU(msg.PDUGetResponse, p.reqID, 0, 0, p.varbinds)
	out, err := msg.BuildV1V2c(p.ver, p.community, resp)
	if err != nil {
		m.log.Warn("build inform confirmation", zap.Error(err))
		return
	}
	m.socksMu.Lock()
	conn := m.trapConn
	m.socksMu.Unlock()
	if conn == nil {
		return
	}
	if _, werr := conn.WriteToUDP(out, p.addr); werr != nil && m.log != nil {
		m.log.Warn("deliver inform confirmation", zap.Error(werr))
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

// reqCtx returns the one send context, created on first use.
//
// The lazy init is behind a sync.Once because two readers reach it
// concurrently (the request leg and the trap leg), and an unsynchronised
// double-initialisation is both a data race and a leaked watcher goroutine.
func (m *Manager) reqCtx() context.Context {
	m.baseOnce.Do(func() {
		m.jobCtx, m.baseCancel = m.ctxPair()
	})
	return m.jobCtx
}

func (m *Manager) trapCtx() context.Context {
	return m.reqCtx()
}
