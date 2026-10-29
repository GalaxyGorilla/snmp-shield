// front_idle_test.go (package tsm): the front-leg idle bound, pinned without
// waiting two minutes.
//
// Every TSM front session holds a slot in the session cap, and DTLS carries
// no keepalive of its own. A peer that crashes, is unplugged or loses its
// route therefore leaves Read blocked forever, which means a slot is never
// released — with the default cap, 64 vanished clients deny the service the
// cap exists to preserve. serveFront arms a read deadline per iteration for
// exactly that reason; this test shortens the constant and drives the
// function over an in-memory conn so the behaviour is checked in
// milliseconds.
package tsm

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// withFrontIdle shrinks frontIdleTimeout for one test. The constant is a
// package variable only so this test can compress the wait; production never
// rewrites it, and no test in this package runs in parallel.
func withFrontIdle(t *testing.T, d time.Duration) {
	t.Helper()
	old := frontIdleTimeout
	frontIdleTimeout = d
	t.Cleanup(func() { frontIdleTimeout = old })
}

// SetFrontIdleTimeoutForTest is the export_test.go-style bridge for the
// external (package tsm_test) session-cap test.
//
// That test waits for a closed session's slot to come back. On a lost DTLS
// close_notify the only bound is frontIdleTimeout — two minutes in
// production, far past any sane test wait — so the test shortens it and
// asserts the real property: the slot is released by the idle bound, not
// "eventually".
func SetFrontIdleTimeoutForTest(t *testing.T, d time.Duration) {
	t.Helper()
	withFrontIdle(t, d)
}

// TestServeFrontReleasesIdleSession: a session that stops sending must end on
// its own, so its cap slot is returned.
func TestServeFrontReleasesIdleSession(t *testing.T) {
	withFrontIdle(t, 120*time.Millisecond)

	g := &TSMGateway{log: zap.NewNop()}
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		g.serveFront(server)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveFront never returned for an idle session: a vanished peer would hold its cap slot forever")
	}

	// The session conn must be closed on the way out (serveFront defers it),
	// otherwise the peer keeps a half-open DTLS association forever. On a
	// net.Pipe the peer side reports that as a closed pipe.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("the front session conn is still open after the idle timeout")
	}
}

// TestServeFrontKeepsActiveSession: traffic must extend the deadline. A
// manager that polls more often than the idle timeout keeps its session
// (otherwise every request would pay a fresh handshake).
func TestServeFrontKeepsActiveSession(t *testing.T) {
	withFrontIdle(t, 300*time.Millisecond)

	g := &TSMGateway{log: zap.NewNop()}
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		g.serveFront(server)
		close(done)
	}()

	// A garbage datagram is enough: the loop only has to read it. Five writes
	// spread over ~1.5x the idle timeout: the session must survive every
	// gap, which fails if the deadline were armed once instead of per read.
	for i := 0; i < 5; i++ {
		if _, err := client.Write([]byte{0x30, 0x00}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(90 * time.Millisecond)
		select {
		case <-done:
			t.Fatalf("serveFront ended after %d datagram(s) although traffic kept arriving", i+1)
		default:
		}
	}

	// Going quiet must then end it.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveFront did not end after traffic stopped; the idle bound is not re-armed")
	}
}
