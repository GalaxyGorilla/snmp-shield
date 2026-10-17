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
}

// NewClientSession creates a client (dialing) session. It connects lazily
// on first use and reconnects with backoff on errors.
func NewClientSession(dial *Dialer, maxPayload, chunk int, log *zap.Logger) *Session {
	return &Session{
		dial:       dial,
		maxPayload: maxPayload,
		chunk:      chunk,
		log:        log,
		chunker:    NewChunker(maxPayload),
		subs:       make(map[uint8]map[chan *Frame]struct{}),
		readStop:   make(chan struct{}),
	}
}

// NewServerSession wraps one accepted transport connection into a Session.
func NewServerSession(conn net.Conn, maxPayload, chunk int, log *zap.Logger) *Session {
	s := &Session{
		conn:       conn,
		maxPayload: maxPayload,
		chunk:      chunk,
		log:        log,
		chunker:    NewChunker(maxPayload),
		subs:       make(map[uint8]map[chan *Frame]struct{}),
		readStop:   make(chan struct{}),
	}
	s.startReadLoop()
	return s
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
	if s.log != nil {
		s.log.Warn("tunnel connection error", zap.Error(err))
	}
	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
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
	max := 5 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := s.dial.Dial(ctx, s.dial.RemoteAddr)
		if err == nil {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = conn.Close()
				return ErrClosed
			}
			s.conn = conn
			s.mu.Unlock()
			s.startReadLoop()
			return nil
		}
		if s.log != nil {
			s.log.Warn("tunnel reconnect failed; backing off", zap.Duration("backoff", backoff), zap.Error(err))
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
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := readFull(conn, hdr); err != nil {
			if isTimeout(err) {
				// Idle link: probe with PING (client) or just re-check.
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
					return
				}
				continue
			}
		}
		switch f.Type {
		case TypePING:
			_ = s.Send(context.Background(), TypePONG, 0, f.CorrID, nil)
			continue
		case TypePONG:
			continue
		case TypeGOAWAY:
			s.dropConn(errors.New("peer sent GOAWAY"))
			if s.dial == nil {
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
		s.dispatch(f)
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
	if conn != nil {
		return conn.Close()
	}
	return nil
}
