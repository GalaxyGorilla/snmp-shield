// Package tunnel: buffered connection wrapper. DTLS (and TLS record)
// connections preserve message boundaries per Read; the session layer
// needs a plain byte stream. This wrapper reads one record at a time and
// buffers the remainder, giving io.ReadFull-compatible semantics without
// losing bytes.
package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// streamConn wraps a packet-boundary-preserving conn (DTLS) into a
// buffered byte stream.
type streamConn struct {
	conn net.Conn

	mu  sync.Mutex
	buf []byte // unconsumed bytes of the last record
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

// PeerCertConn is implemented by connections that can report the peer
// certificate chain after the handshake (TSM maps this chain to a
// securityName per RFC 5591).
type PeerCertConn interface {
	PeerCerts() []*x509.Certificate
}

// peerCerts returns the peer certificate chain of the underlying conn,
// or nil when the transport does not expose one.
func (s *streamConn) peerCerts() []*x509.Certificate {
	switch c := s.conn.(type) {
	case *dtls.Conn:
		st, ok := c.ConnectionState()
		if !ok {
			return nil
		}
		return parseDERCerts(st.PeerCertificates)
	case *tls.Conn:
		return c.ConnectionState().PeerCertificates
	default:
		return nil
	}
}

// parseDERCerts decodes DER-encoded certificates (pion/dtls exposes them
// as raw bytes).
func parseDERCerts(der [][]byte) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(der))
	for _, d := range der {
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			return nil
		}
		out = append(out, cert)
	}
	return out
}

// PeerCerts implements PeerCertConn.
func (s *streamConn) PeerCerts() []*x509.Certificate { return s.peerCerts() }

func (s *streamConn) Write(p []byte) (int, error)        { return s.conn.Write(p) }
func (s *streamConn) Close() error                       { return s.conn.Close() }
func (s *streamConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *streamConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *streamConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
