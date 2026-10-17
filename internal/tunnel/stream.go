// Package tunnel: buffered connection wrapper. DTLS (and TLS record)
// connections preserve message boundaries per Read; the session layer
// needs a plain byte stream. This wrapper reads one record at a time and
// buffers the remainder, giving io.ReadFull-compatible semantics without
// losing bytes.
package tunnel

import (
	"net"
	"sync"
	"time"
)

// streamConn wraps a packet-boundary-preserving conn (DTLS) into a
// buffered byte stream.
type streamConn struct {
	conn net.Conn

	mu   sync.Mutex
	buf  []byte // unconsumed bytes of the last record
}

// newStreamConn wraps conn unless it is already a stream (TCP/TLS).
func newStreamConn(conn net.Conn, packet bool) net.Conn {
	if !packet {
		return conn
	}
	return &streamConn{conn: conn}
}

// Read implements net.Conn with stream semantics over record reads.
func (s *streamConn) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 {
		rec := make([]byte, 65536)
		n, err := s.conn.Read(rec)
		if err != nil {
			return 0, err
		}
		s.buf = rec[:n]
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *streamConn) Write(p []byte) (int, error)         { return s.conn.Write(p) }
func (s *streamConn) Close() error                        { return s.conn.Close() }
func (s *streamConn) LocalAddr() net.Addr                 { return s.conn.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr                { return s.conn.RemoteAddr() }
func (s *streamConn) SetDeadline(t time.Time) error       { return s.conn.SetDeadline(t) }
func (s *streamConn) SetReadDeadline(t time.Time) error   { return s.conn.SetReadDeadline(t) }
func (s *streamConn) SetWriteDeadline(t time.Time) error  { return s.conn.SetWriteDeadline(t) }
