package tunnel

import (
	"context"
	"testing"
	"time"
)

// TestDTLSPSKHandshakeLoopback verifies the PSK-DTLS client/server handshake
// on loopback through the session layer. The accepted server conn must be
// served by a Session (readLoop) — in pion/dtls v3 the server-side handshake
// only starts once Read/Write is called on the server conn, which is exactly
// what the real proxy does via NewServerSession.
func TestDTLSPSKHandshakeLoopback(t *testing.T) {
	psk := []byte("minimal-psk")
	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("min"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	accCh := make(chan error, 1)
	srvReady := make(chan struct{})
	go func() {
		c, aerr := l.Accept()
		if aerr != nil {
			accCh <- aerr
			return
		}
		// Serve the conn like the real proxy: a server session whose
		// readLoop starts the server handshake and answers PINGs.
		srvSess := NewServerSession(c, 65536, 1200, nil)
		defer srvSess.Close()
		close(srvReady)
		accCh <- nil
		// Keep the session alive until the test finishes.
		<-srvSess.readStop
	}()

	d := &Dialer{
		Mode:        "dtls",
		RemoteAddr:  l.Addr().String(),
		PSK:         psk,
		PSKIdentity: []byte("min"),
		Timeout:     5 * time.Second,
	}
	sess := NewClientSession(d, 65536, 1200, nil)
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case err := <-accCh:
		if err != nil {
			t.Fatalf("accept error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("accept timeout")
	}
}
