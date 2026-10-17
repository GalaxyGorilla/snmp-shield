// failover_test.go: HA tests — endpoint failover walk (sticky) and
// session dead-peer detection.
package tunnel

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// serverSet tracks the server sessions created by one listener so a
// test can kill the endpoint (listener + accepted sessions) at once.
type serverSet struct {
	mu   sync.Mutex
	sess []*Session
}

func (s *serverSet) add(sess *Session) {
	s.mu.Lock()
	s.sess = append(s.sess, sess)
	s.mu.Unlock()
}

// kill closes every tracked server session (the listener itself is
// closed separately).
func (s *serverSet) kill() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sess {
		_ = sess.Close()
	}
}

// serveListener accepts conns until cancel fires or the listener closes;
// every accepted conn is served with a server session registered in set.
// Each server session echoes TypeREQ frames back (test liveness probe).
func serveListener(l net.Listener, cancel <-chan struct{}, wg *sync.WaitGroup, set *serverSet) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sess := NewServerSession(conn, 65536, 1200, zap.NewNop())
				set.add(sess)
				ch, cancelSub := sess.Subscribe(TypeREQ)
				go func() {
					for f := range ch {
						_ = sess.Send(context.Background(), TypeREQ, f.Flags, f.CorrID, f.Payload)
					}
				}()
				<-cancel
				cancelSub()
				_ = sess.Close()
			}()
		}
	}()
}

// freeListener binds a DTLS PSK listener on an ephemeral port.
func freeListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l
}

func TestClientFailover(t *testing.T) {
	lA := freeListener(t)
	lB := freeListener(t)
	addrA, addrB := lA.Addr().String(), lB.Addr().String()
	cancel := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(cancel)
		_ = lA.Close()
		_ = lB.Close()
		wg.Wait()
	}()
	setA := &serverSet{}
	setB := &serverSet{}
	serveListener(lA, cancel, &wg, setA)
	serveListener(lB, cancel, &wg, setB)

	met := observ.NewMetrics()
	dial := &Dialer{
		Mode:        "dtls",
		RemoteAddrs: []string{addrA, addrB},
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
		Timeout:     2 * time.Second,
	}
	sess := NewClientSession(dial, 65536, 1200, zap.NewNop())
	sess.SetMetrics(met)
	sess.SetTuning(300*time.Millisecond, 200*time.Millisecond)
	defer sess.Close()

	ctx, cancelCtx := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelCtx()
	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("initial connect: %v", err)
	}

	// The client should be pinned to A (most preferred).
	if got := sess.current().RemoteAddr().String(); got != addrA {
		t.Fatalf("expected conn to %s, got %s", addrA, got)
	}
	dial.failMu.Lock()
	idx := dial.failIdx
	dial.failMu.Unlock()
	if idx != 0 {
		t.Fatalf("expected failIdx 0, got %d", idx)
	}

	// Kill A: close the listener AND its accepted server sessions. The
	// server session close makes the client readLoop see EOF → dropConn
	// → reconnect: the A dial fails (listener closed), B succeeds.
	_ = lA.Close()
	setA.kill()

	// Wait for failover to B.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c := sess.current()
		if c != nil && c.RemoteAddr().String() == addrB {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c := sess.current()
	if c == nil {
		t.Fatal("no connection after failover window")
	}
	got := c.RemoteAddr().String()
	if got != addrB {
		t.Fatalf("expected failover to %s, still on %s", addrB, got)
	}

	// Sticky index updated.
	dial.failMu.Lock()
	idx = dial.failIdx
	dial.failMu.Unlock()
	if idx != 1 {
		t.Fatalf("expected failIdx 1 after failover, got %d", idx)
	}

	// Metrics: reconnects counted, tunnel reported up.
	if n := testutil.ToFloat64(met.Reconnects); n < 1 {
		t.Fatalf("expected Reconnects >= 1, got %v", n)
	}
	if n := testutil.ToFloat64(met.TunnelUp); n != 1 {
		t.Fatalf("expected TunnelUp 1, got %v", n)
	}

	// Liveness: a request frame must reach B's server session.
	ch, cancelSub := sess.Subscribe(TypeREQ)
	defer cancelSub()
	if err := sess.Send(ctx, TypeREQ, 0, 7, []byte("ping")); err != nil {
		t.Fatalf("send after failover: %v", err)
	}
	select {
	case f := <-ch:
		if f.CorrID != 7 {
			t.Fatalf("corrupted frame: corrID %d", f.CorrID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("frame not received after failover (link dead)")
	}
}

// TestSessionDeadPeerPipe: a server session over a silent net.Pipe with
// keepalive tuning declares the peer dead (Done fires) after
// maxIdleMisses idle timeouts.
func TestSessionDeadPeerPipe(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	sess := NewServerSession(server, 65536, 1200, zap.NewNop())
	defer sess.Close()
	sess.SetTuning(200*time.Millisecond, 0)

	// No data flows: 3 consecutive idle timeouts at 600ms each ≈ 1.8s.
	select {
	case <-sess.Done():
		// dead peer detected and connection dropped
	case <-time.After(8 * time.Second):
		t.Fatal("Done() did not fire for a silent dead peer")
	}
}
