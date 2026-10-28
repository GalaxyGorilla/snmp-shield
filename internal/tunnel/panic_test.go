// panic_test.go — panic containment at the session boundary.
//
// safego_test.go proves the helper works in isolation; these tests prove it
// is wired into the paths that matter. The event callback is the cheapest
// such path to drive with a real panic: it runs on the read loop (TunnelDown)
// and on the connect path (TunnelUp), and snmp-shield's own callback
// (metrics + trap send) is exactly the kind of code that could break.
//
// What "contained" must mean, and what is asserted here:
//  1. a panicking TunnelUp callback does not fail Connect or the session;
//  2. a panicking TunnelDown callback does not skip the shutdown path —
//     Done() still fires, so per-session work is still cancelled (a silent
//     skip there would leak a translator per reconnect).
package tunnel

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// listenerPair starts a PSK-DTLS listener and serves one accepted conn with
// the given session setup. It returns the listen address and a channel that
// yields the server session (so a test can observe its lifecycle).
func listenerPair(t *testing.T, log *zap.Logger, setup func(*Session)) (string, <-chan *Session) {
	t.Helper()
	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	sessCh := make(chan *Session, 1)
	go func() {
		conn, aerr := l.Accept()
		if aerr != nil {
			return
		}
		sess := NewServerSession(conn, 65536, 1200, log)
		t.Cleanup(func() { _ = sess.Close() })
		sess.SetTuning(200*time.Millisecond, 0)
		if setup != nil {
			// Register before the test can observe the session, so a
			// callback is in place for the very first lifecycle event.
			setup(sess)
		}
		sessCh <- sess
	}()
	return l.Addr().String(), sessCh
}

// TestPanickingTunnelUpCallbackKeepsSessionUsable: the up event fires on the
// connect path. A panic there must not surface as a Connect error, and the
// session must still carry frames afterwards.
func TestPanickingTunnelUpCallbackKeepsSessionUsable(t *testing.T) {
	addr, _ := listenerPair(t, zap.NewNop(), func(sess *Session) {
		go func() {
			ch, cancel := sess.Subscribe(TypeREQ)
			defer cancel()
			select {
			case f := <-ch:
				_ = sess.Send(context.Background(), TypeREQ, f.Flags, f.CorrID, f.Payload)
			case <-time.After(5 * time.Second):
			}
		}()
	})

	core, logs := observer.New(zapcore.DebugLevel)
	dial := &Dialer{
		Mode:        "dtls",
		RemoteAddr:  addr,
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
		Timeout:     5 * time.Second,
	}
	sess := NewClientSession(dial, 65536, 1200, zap.New(core))
	defer func() { _ = sess.Close() }()

	panicked := make(chan struct{})
	var once bool
	sess.SetEventFunc(func(Event) {
		if !once {
			once = true
			close(panicked)
			panic("metrics bookkeeping exploded")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A panicking up-callback must not turn into a Connect failure.
	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("Connect failed after a panicking TunnelUp callback: %v", err)
	}
	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("the TunnelUp callback never ran; the test is not exercising the panic path")
	}

	// The session must still work: send a frame and get the echo.
	ch, unsub := sess.Subscribe(TypeREQ)
	defer unsub()
	if err := sess.Send(ctx, TypeREQ, 0, 7, []byte("still alive")); err != nil {
		t.Fatalf("Send after callback panic: %v", err)
	}
	select {
	case f := <-ch:
		if string(f.Payload) != "still alive" {
			t.Fatalf("echo payload = %q", f.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no echo after a panicking event callback: the session stalled")
	}

	// And the recovery must be loud.
	if n := logs.FilterMessage("recovered panic in tunnel event callback").Len(); n != 1 {
		t.Fatalf("got %d recovery log entries, want 1 (all: %v)", n, logs.All())
	}
}

// TestPanickingTunnelDownCallbackStillFiresDone: the down event fires from
// the read loop's teardown. If the panic escaped, the read loop would die
// before closeDone, Done() would never fire, and the per-session translator
// would leak. Assert Done() still fires.
func TestPanickingTunnelDownCallbackStillFiresDone(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	downDone := make(chan struct{})
	addr, sessCh := listenerPair(t, zap.New(core), func(sess *Session) {
		sess.SetEventFunc(func(ev Event) {
			if ev.Kind == EventTunnelDown {
				close(downDone)
				panic("trap bookkeeping exploded")
			}
		})
	})

	dial := &Dialer{
		Mode:        "dtls",
		RemoteAddr:  addr,
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
		Timeout:     5 * time.Second,
	}
	client := NewClientSession(dial, 65536, 1200, zap.NewNop())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Drop the client hard: the server sees an error, tears down, and
	// fires TunnelDown from inside the read loop.
	_ = client.Close()

	select {
	case <-downDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never fired TunnelDown")
	}
	// The recovery is logged from the read-loop goroutine.
	if !waitForLog(logs, "recovered panic in tunnel event callback", 3*time.Second) {
		t.Fatalf("no recovery log after a panicking TunnelDown callback (all: %v)", logs.All())
	}
	// The shutdown path must still complete: Done() closes.
	server := <-sessCh
	select {
	case <-server.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done() never fired: the recovered panic skipped the teardown")
	}
}

func waitForLog(logs *observer.ObservedLogs, msg string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if logs.FilterMessage(msg).Len() == 1 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
