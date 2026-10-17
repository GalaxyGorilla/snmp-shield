// challenge_test.go (package tunnel): adversarial tests beyond the happy
// paths — a wrong PSK must fail the DTLS handshake (client Connect
// error), proving the tunnel never accepts unauthenticated peers.
package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestPskWrongKeyRejected(t *testing.T) {
	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode: "dtls", PSK: []byte("correct-psk"), PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	// Serve every accepted conn like the real proxy: after a failed
	// handshake the client retries with a fresh UDP port, and pion's
	// listener creates a new accepted conn per remote address.
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			srvSess := NewServerSession(c, 65536, 1200, nil)
			go func() {
				defer srvSess.Close()
				<-srvSess.readStop
			}()
		}
	}()

	d := &Dialer{
		Mode:        "dtls",
		RemoteAddr:  l.Addr().String(),
		PSK:         []byte("wrong-psk"), // differs from the listener's
		PSKIdentity: []byte("id"),
		Timeout:     2 * time.Second,
	}
	sess := NewClientSession(d, 65536, 1200, nil)
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sess.Connect(ctx); err == nil {
		t.Fatal("wrong-PSK client connected; want handshake failure")
	}
}
