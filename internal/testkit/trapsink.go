package testkit

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// TrapSink is a UDP listener that records notifications. Tests use it as the
// manager-side trap receiver: the proxy's job is to deliver a datagram, and
// the assertions are about what arrived, not about which library sent it.
type TrapSink struct {
	conn net.PacketConn

	// answerInforms makes the sink behave like a real manager: a v2c
	// inform is confirmed with a GetResponse echoing req-id and community.
	// Without this an inform relay can only ever time out, which makes the
	// confirmation path untestable.
	answerInforms bool

	mu   sync.Mutex
	seen [][]byte
	sig  chan struct{}
}

// NewTrapSink binds an ephemeral loopback port.
func NewTrapSink(t testing.TB) *TrapSink {
	return newTrapSink(t, false)
}

// NewAnsweringTrapSink is NewTrapSink plus v2c inform confirmation.
func NewAnsweringTrapSink(t testing.TB) *TrapSink {
	return newTrapSink(t, true)
}

func newTrapSink(t testing.TB, answerInforms bool) *TrapSink {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testkit: trap sink bind: %v", err)
	}
	s := &TrapSink{conn: conn, sig: make(chan struct{}, 1), answerInforms: answerInforms}
	go s.read()
	t.Cleanup(func() { _ = conn.Close() })
	return s
}

// Addr is the sink's host:port.
func (s *TrapSink) Addr() string { return s.conn.LocalAddr().String() }

// Count is how many datagrams arrived.
func (s *TrapSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// Datagrams returns a copy of everything received.
func (s *TrapSink) Datagrams() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.seen))
	copy(out, s.seen)
	return out
}

// WaitFor blocks until at least n datagrams have arrived. It fails the test
// on timeout with the count it did see.
func (s *TrapSink) WaitFor(t testing.TB, n int, timeout time.Duration) [][]byte {
	t.Helper()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.After(timeout)
	for {
		if got := s.Count(); got >= n {
			return s.Datagrams()
		}
		select {
		case <-s.sig:
		case <-deadline:
			t.Fatalf("testkit: trap sink saw %d datagram(s), want %d", s.Count(), n)
			return nil
		}
	}
}

// WaitForTrapOID waits for a datagram whose notification OID matches oid.
// This is the assertion trap-direction tests actually want: "the proxy
// delivered *this* trap", not merely "something arrived".
func (s *TrapSink) WaitForTrapOID(t testing.TB, oid string, timeout time.Duration) []byte {
	t.Helper()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, dg := range s.Datagrams() {
			if got, ok := msg.TrapOID(dg); ok && got == oid {
				return dg
			}
		}
		select {
		case <-s.sig:
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("testkit: no notification with trap OID %s in %d datagram(s) after %s: %v",
		oid, s.Count(), timeout, trapOIDs(s.Datagrams()))
	return nil
}

func trapOIDs(dgs [][]byte) []string {
	out := make([]string, 0, len(dgs))
	for _, dg := range dgs {
		if oid, ok := msg.TrapOID(dg); ok {
			out = append(out, oid)
		} else {
			out = append(out, "<undecodable>")
		}
	}
	return out
}

func (s *TrapSink) read() {
	buf := make([]byte, 65536)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		s.mu.Lock()
		s.seen = append(s.seen, dg)
		s.mu.Unlock()
		select {
		case s.sig <- struct{}{}:
		default:
		}
		if s.answerInforms {
			s.confirmInform(dg, from)
		}
	}
}

// confirmInform answers a v2c inform the way any manager would: the same
// req-id, the same community, the same varbinds and error status.
func (s *TrapSink) confirmInform(dg []byte, from net.Addr) {
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsInform(info.PDUType) {
		return
	}
	version, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}
	_, fields, err := msg.ParsePDU(pduTLV)
	if err != nil {
		return
	}
	resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(version, community, resp)
	if err != nil {
		return
	}
	_, _ = s.conn.WriteTo(out, from)
}
