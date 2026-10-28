// Package tunnel: session layer. A Session wraps one tunnel transport
// connection and provides frame send/recv, PING/PONG keepalive, and
// automatic reconnect with exponential backoff on the client side.
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/safego"
	"go.uber.org/zap"
)

// Errors.
var (
	ErrClosed = errors.New("tunnel: session closed")
	ErrNoConn = errors.New("tunnel: no connection")
)

// Session is a framed, multiplexed tunnel session over one transport
// connection, with keepalive and (client-side) auto-reconnect.
type Session struct {
	dial       *Dialer // non-nil for client sessions (reconnect)
	maxPayload int
	chunk      int
	log        *zap.Logger

	chunker *Chunker // reassembles fragmented inbound frames (single reader)

	mu     sync.Mutex
	conn   net.Conn
	closed bool

	subsMu sync.Mutex
	subs   map[uint8]map[chan *Frame]struct{} // frame type -> subscriber channels

	readLoopOnce sync.Once
	readStop     chan struct{}

	// keepalive interval; read deadline = 3×keepalive. 0 = defaultKeepalive.
	keepalive time.Duration
	// maxBackoff caps the reconnect backoff. 0 = defaultMaxBackoff.
	maxBackoff time.Duration
	// met is the optional metrics set (Reconnects counter, TunnelUp gauge).
	met *observ.Metrics

	// doneCh is closed when the session is closed or its connection is
	// irrecoverably lost (server side). Guarded by doneOnce.
	doneOnce sync.Once
	doneCh   chan struct{}

	// idleMisses counts consecutive idle read timeouts for dead-peer
	// detection. Guarded by mu.
	idleMisses int

	// onEvent is the optional lifecycle event callback (tunnel up/down,
	// failover). Set via SetEventFunc; called from arbitrary goroutines,
	// so implementations must be safe for concurrent use.
	onEvent func(Event)

	// lastFailIdx is the last seen dialer failover index (-1 = none yet),
	// used to detect endpoint switches (EventFailover). Guarded by mu.
	lastFailIdx int
}

// Session defaults: used when SetTuning is given a zero value. They match
// the config defaults (keepalive_secs 10, max_reconnect_backoff 30s) so a
// session behaves the same whether or not the caller passed tuning.
const (
	defaultKeepalive  = 10 * time.Second
	defaultMaxBackoff = 30 * time.Second

	deadlinePerKeepalive = 3
	maxIdleMisses        = 3
)

// Event is a tunnel session lifecycle event delivered to the callback
// registered via SetEventFunc.
type Event struct {
	Kind EventKind
	// Endpoint is the peer address involved (tunnel-up/failover: the
	// dialed endpoint; tunnel-down: the dropped peer when known).
	Endpoint string
}

// EventKind enumerates the session lifecycle events.
type EventKind uint8

const (
	// EventTunnelUp fires after a transport connection was established.
	EventTunnelUp EventKind = iota
	// EventTunnelDown fires when the transport connection was lost
	// (error, dead peer, GOAWAY) or the session was closed.
	EventTunnelDown
	// EventFailover fires when a reconnect pinned a DIFFERENT endpoint
	// than the previously active one (HA failover happened).
	EventFailover
)

// NewClientSession creates a client (dialing) session. It connects lazily
// on first use and reconnects with backoff on errors.
func NewClientSession(dial *Dialer, maxPayload, chunk int, log *zap.Logger) *Session {
	return &Session{
		dial:        dial,
		maxPayload:  maxPayload,
		chunk:       chunk,
		log:         log,
		chunker:     NewChunker(maxPayload),
		subs:        make(map[uint8]map[chan *Frame]struct{}),
		readStop:    make(chan struct{}),
		doneCh:      make(chan struct{}),
		lastFailIdx: -1,
	}
}

// NewServerSession wraps one accepted transport connection into a Session.
func NewServerSession(conn net.Conn, maxPayload, chunk int, log *zap.Logger) *Session {
	s := &Session{
		conn:        conn,
		maxPayload:  maxPayload,
		chunk:       chunk,
		log:         log,
		chunker:     NewChunker(maxPayload),
		subs:        make(map[uint8]map[chan *Frame]struct{}),
		readStop:    make(chan struct{}),
		doneCh:      make(chan struct{}),
		lastFailIdx: -1,
	}
	s.startReadLoop()
	return s
}

// SetTuning configures keepalive-based dead-peer detection: the read
// deadline becomes 3×keepalive and after maxIdleMisses consecutive idle
// timeouts the connection is dropped (server side) or probed then dropped
// (client side). maxBackoff caps the reconnect backoff. A zero value falls
// back to the package default (defaultKeepalive / defaultMaxBackoff), so
// dead-peer detection is always active — there is no "never detect" mode.
func (s *Session) SetTuning(keepalive, maxBackoff time.Duration) {
	s.mu.Lock()
	s.keepalive = keepalive
	s.maxBackoff = maxBackoff
	s.mu.Unlock()
}

// SetMetrics attaches the metrics set used for Reconnects/TunnelUp.
func (s *Session) SetMetrics(met *observ.Metrics) {
	s.met = met
}

// SetEventFunc registers the lifecycle event callback (tunnel up/down,
// failover). Called from arbitrary goroutines; f must be safe for
// concurrent use. nil disables callbacks.
func (s *Session) SetEventFunc(f func(Event)) {
	s.mu.Lock()
	s.onEvent = f
	s.mu.Unlock()
}

// emit invokes the event callback when one is registered. The endpoint
// is read from the current connection (best effort).
//
// The callback runs under safego.Dispatch: it is called from the read loop
// and the reconnect path, so a panic in a consumer (metrics bookkeeping, a
// trap send) would otherwise take down the session or the whole process.
// A panicking callback is a bug and is logged as one, but the tunnel keeps
// running.
func (s *Session) emit(kind EventKind) {
	s.mu.Lock()
	f := s.onEvent
	var ep string
	if s.conn != nil {
		ep = s.conn.RemoteAddr().String()
	}
	s.mu.Unlock()
	if f != nil {
		safego.Dispatch(s.log, "tunnel event callback", func() {
			f(Event{Kind: kind, Endpoint: ep})
		})
	}
}

// Done returns a channel closed when the session is closed or its
// connection is irrecoverably lost (server side). Callers use it to
// cancel per-session work (translators).
func (s *Session) Done() <-chan struct{} {
	return s.doneCh
}

// closeDone fires the Done channel once.
func (s *Session) closeDone() {
	s.doneOnce.Do(func() { close(s.doneCh) })
}

// readDeadline returns the per-read timeout: 3×keepalive, or 3× the default
// keepalive when no tuning was supplied.
func (s *Session) readDeadline() time.Duration {
	s.mu.Lock()
	keepalive := s.keepalive
	s.mu.Unlock()
	if keepalive <= 0 {
		keepalive = defaultKeepalive
	}
	return keepalive * deadlinePerKeepalive
}

// backoffCap returns the reconnect backoff cap.
func (s *Session) backoffCap() time.Duration {
	s.mu.Lock()
	maxBackoff := s.maxBackoff
	s.mu.Unlock()
	if maxBackoff <= 0 {
		return defaultMaxBackoff
	}
	return maxBackoff
}

// PeerCerts reports the peer certificate chain of the tunnel connection,
// or nil when the transport does not provide certificates (PSK mode) or
// the handshake has not completed. For server sessions the handshake
// completes on the first Read, so call this after the first frame.
func (s *Session) PeerCerts() []*x509.Certificate {
	c := s.current()
	if c == nil {
		return nil
	}
	if pc, ok := c.(PeerCertConn); ok {
		return pc.PeerCerts()
	}
	// TLS mode wraps nothing: the raw *tls.Conn carries the state.
	if tc, ok := c.(*tls.Conn); ok {
		return tc.ConnectionState().PeerCertificates
	}
	return nil
}

// Connect eagerly establishes the tunnel connection (client sessions).
// Without it the session connects lazily on first Send. After the
// handshake it sends a PING: pion/dtls's server-side handshake (listener
// Accept) only completes once the client sends an application record.
func (s *Session) Connect(ctx context.Context) error {
	if s.dial == nil {
		return nil // server sessions are already connected
	}
	if s.current() != nil {
		return nil
	}
	if err := s.reconnect(ctx); err != nil {
		return err
	}
	// Kick the server handshake with a PING (session-safe write).
	return s.Send(ctx, TypePING, 0, 0, nil)
}

// Subscribe registers a channel for frames of the given type. The
// returned cancel function unregisters it.
func (s *Session) Subscribe(ftype uint8) (<-chan *Frame, func()) {
	ch := make(chan *Frame, 64)
	s.subsMu.Lock()
	if s.subs[ftype] == nil {
		s.subs[ftype] = make(map[chan *Frame]struct{})
	}
	s.subs[ftype][ch] = struct{}{}
	s.subsMu.Unlock()
	cancel := func() {
		s.subsMu.Lock()
		defer s.subsMu.Unlock()
		if m, ok := s.subs[ftype]; ok {
			delete(m, ch)
		}
	}
	return ch, cancel
}

// dispatch delivers one frame to all subscribers of its type.
func (s *Session) dispatch(f *Frame) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs[f.Type] {
		select {
		case ch <- f:
		default: // slow subscriber: drop rather than block the read loop
		}
	}
}

// Send writes one frame, fragmenting the payload as needed and writing
// each wire frame separately (a single DTLS record is limited by the
// link MTU, so the fragment frames must go out as individual writes).
func (s *Session) Send(ctx context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	if len(payload) > s.maxPayload {
		return ErrTooLarge
	}
	frames := Fragment(typ, flags, corrID, payload, s.chunk)
	for _, f := range frames {
		if err := s.writeAll(ctx, f.Marshal()); err != nil {
			return err
		}
	}
	return nil
}

// writeAll writes marshalled frames to the current connection,
// reconnecting on failure (client sessions only).
func (s *Session) writeAll(ctx context.Context, data []byte) error {
	for {
		conn := s.current()
		if conn == nil {
			if s.dial == nil {
				return ErrNoConn
			}
			if err := s.reconnect(ctx); err != nil {
				return err
			}
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(data); err != nil {
			s.dropConn(err)
			if s.dial == nil {
				return err
			}
			continue
		}
		return nil
	}
}

// current returns the live connection or nil.
func (s *Session) current() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.conn
}

// dropConn discards the current connection after an error.
func (s *Session) dropConn(err error) {
	s.mu.Lock()
	if s.log != nil {
		s.log.Warn("tunnel connection error", zap.Error(err))
	}
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
	if s.met != nil {
		s.met.TunnelUp.Set(0)
	}
	s.emit(EventTunnelDown)
}

// reconnect dials a new transport connection (client sessions).
func (s *Session) reconnect(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.conn != nil {
		s.mu.Unlock()
		return nil // another goroutine already reconnected
	}
	s.mu.Unlock()

	backoff := 100 * time.Millisecond
	max := s.backoffCap()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := s.dial.Dial(ctx, s.dial.RemoteAddr)
		if err == nil {
			// Failover detection: the dialer pins its sticky index; a
			// change means the endpoint switched (HA failover).
			failedOver := s.failoverChanged()
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = conn.Close()
				return ErrClosed
			}
			s.conn = conn
			s.mu.Unlock()
			s.startReadLoop()
			if s.met != nil {
				s.met.Reconnects.Inc()
				s.met.TunnelUp.Set(1)
			}
			if failedOver {
				s.emit(EventFailover)
			}
			s.emit(EventTunnelUp)
			return nil
		}
		if s.log != nil {
			s.log.Warn("tunnel reconnect failover", zap.Duration("backoff", backoff), zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > max {
			backoff = max
		}
	}
}

// startReadLoop launches the inbound frame reader once.
func (s *Session) startReadLoop() {
	s.readLoopOnce.Do(func() {
		go s.readLoop()
	})
}

// failoverChanged reports whether the dialer's sticky failover index
// differs from the last recorded one, updating the record. Always false
// (and no state) for single-endpoint or server sessions.
func (s *Session) failoverChanged() bool {
	if s.dial == nil || len(s.dial.RemoteAddrs) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.dial.currentIdx()
	if s.lastFailIdx != idx {
		// The very first successful dial (lastFailIdx unset, -1) is not
		// a failover.
		first := s.lastFailIdx < 0
		s.lastFailIdx = idx
		return !first
	}
	return false
}

// readLoop reads frames from the connection and dispatches them.
func (s *Session) readLoop() {
	hdr := make([]byte, frameHeaderLen)
	for {
		conn := s.current()
		if conn == nil {
			if s.dial == nil {
				return // server session lost its conn: done
			}
			if err := s.reconnect(context.Background()); err != nil {
				return
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(s.readDeadline()))
		if _, err := readFull(conn, hdr); err != nil {
			if isTimeout(err) {
				// Idle link: count the miss. The client probes with PING;
				// after maxIdleMisses consecutive misses the link is dead.
				s.mu.Lock()
				s.idleMisses++
				dead := s.idleMisses >= maxIdleMisses
				s.mu.Unlock()
				if dead {
					if s.log != nil {
						s.log.Warn("tunnel peer idle past detection window; dropping",
							zap.Int("misses", s.idleMisses))
					}
					s.dropConn(errors.New("peer idle: dead peer detected"))
					if s.dial == nil {
						s.closeDone()
						return
					}
				}
				if s.dial != nil {
					_ = s.Send(context.Background(), TypePING, 0, 0, nil)
				}
				continue
			}
			if s.log != nil {
				s.log.Warn("read hdr failed", zap.Error(err))
			}
			s.dropConn(err)
			if s.dial == nil {
				s.closeDone()
				return
			}
			continue
		}
		f, err := UnmarshalHeader(hdr)
		if err != nil {
			if s.log != nil {
				s.log.Warn("unmarshal failed", zap.Error(err), zap.ByteString("hdr", hdr))
			}
			s.dropConn(err)
			if s.dial == nil {
				s.closeDone()
				return
			}
			continue
		}
		plen := int(headerPayloadLen(hdr))
		payload := make([]byte, plen)
		if plen > 0 {
			if _, err := readFull(conn, payload); err != nil {
				s.dropConn(err)
				if s.dial == nil {
					s.closeDone()
					return
				}
				continue
			}
		}
		s.mu.Lock()
		s.idleMisses = 0
		s.mu.Unlock()
		switch f.Type {
		case TypePING:
			_ = s.Send(context.Background(), TypePONG, 0, f.CorrID, nil)
			continue
		case TypePONG:
			continue
		case TypeGOAWAY:
			s.dropConn(errors.New("peer sent GOAWAY"))
			if s.dial == nil {
				s.closeDone()
				return
			}
			continue
		}
		f.Payload = payload
		// Reassemble fragmented frames; single-frame payloads pass through.
		complete, err := s.chunker.Accept(f, time.Now())
		if err != nil {
			if s.log != nil {
				s.log.Warn("reassembly failed", zap.Error(err))
			}
			continue
		}
		if complete == nil {
			continue // waiting for more fragments
		}
		f.Payload = complete
		safego.Dispatch(s.log, "tunnel frame", func() { s.dispatch(f) })
	}
}

// headerPayloadLen extracts the payload length field from a raw header.
func headerPayloadLen(hdr []byte) uint32 {
	return uint32(hdr[9])<<24 | uint32(hdr[10])<<16 | uint32(hdr[11])<<8 | uint32(hdr[12])
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// readFull fills buf from r, honoring deadlines.
func readFull(r net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := r.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Close shuts the session down.
func (s *Session) Close() error {
	s.mu.Lock()
	s.closed = true
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	s.closeDone()
	if conn != nil {
		return conn.Close()
	}
	return nil
}
