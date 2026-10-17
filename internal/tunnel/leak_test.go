// leak_test.go — goroutine-leak regression test for the tunnel session
// layer. Repeated connect / exchange / close cycles must not accumulate
// goroutines: every cycle spawns a client session, a server session and
// their read loops; a production leak (session, translator or pion
// goroutine never released) would show up as a rising runtime count.
package tunnel

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestSessionGoroutineLeak runs repeated connect / exchange / close
// cycles over a real PSK-DTLS loopback pair and asserts the live
// goroutine count returns to baseline. The server side is keyed on
// Session.Done() so each cycle's server goroutines exit when the client
// closes (no test-end accounting noise). Production tuning is mirrored
// server-side (SetTuning(keepalive, 0)) so a session whose client
// vanished self-heals within the dead-peer window.
func TestSessionGoroutineLeak(t *testing.T) {
	const cycles = 30

	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, aerr := l.Accept()
			if aerr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sess := NewServerSession(conn, 65536, 1200, zap.NewNop())
				defer func() { _ = sess.Close() }()
				// Mirror production tuning (proxy.go SetTuning(Keepalive(), 0))
				// so a session whose client vanished self-heals within the
				// dead-peer window instead of the legacy 90s deadline.
				sess.SetTuning(200*time.Millisecond, 0)
				ch, cancelSub := sess.Subscribe(TypeREQ)
				defer cancelSub()
				echoDone := make(chan struct{})
				go func() {
					defer close(echoDone)
					for {
						select {
						case f := <-ch:
							_ = sess.Send(context.Background(), TypeREQ, f.Flags, f.CorrID, f.Payload)
						case <-sess.Done():
							return
						}
					}
				}()
				<-sess.Done() // client closed (or conn died): release everything
				<-echoDone
			}()
		}
	}()

	// let the runtime settle so background goroutines don't pollute the baseline.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()

	dial := &Dialer{
		Mode:        "dtls",
		RemoteAddr:  l.Addr().String(),
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
		Timeout:     2 * time.Second,
	}

	for i := 0; i < cycles; i++ {
		sess := NewClientSession(dial, 65536, 1200, zap.NewNop())
		ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
		if cerr := sess.Connect(ctx); cerr != nil {
			t.Fatalf("cycle %d connect: %v", i, cerr)
		}
		cancelCtx()
		ch, cancelSub := sess.Subscribe(TypeREQ)
		if serr := sess.Send(context.Background(), TypeREQ, 0, 1, []byte("ping")); serr != nil {
			t.Fatalf("cycle %d send: %v", i, serr)
		}
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("cycle %d: no echo", i)
		}
		cancelSub()
		if cerr := sess.Close(); cerr != nil {
			t.Fatalf("cycle %d close: %v", i, cerr)
		}
	}

	// give lingering goroutines a chance to exit, then compare.
	runtime.GC()
	deadline := time.Now().Add(3 * time.Second)
	var after int
	for {
		after = runtime.NumGoroutine()
		if after <= before || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if after > before {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutine leak: before=%d after=%d\n%s", before, after, buf[:n])
	}
	t.Logf("no leak: before=%d after=%d over %d cycles", before, after, cycles)
}
