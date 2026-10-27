package tunnel

import (
	"context"
	"testing"
	"time"
)

// TestSessionEcho exercises the full session layer: client session sends
// REQ frames, server session echoes them back as RESP, client subscriber
// receives them.
func TestSessionEcho(t *testing.T) {
	psk := []byte("echo-psk")
	l, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "dtls", PSK: psk, PSKIdentity: []byte("echo")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// Server side: echo REQ -> RESP.
	srvDone := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		sess := NewServerSession(conn, 65536, 1200, nil)
		defer sess.Close()
		reqCh, cancel := sess.Subscribe(TypeREQ)
		defer cancel()
		srvDone <- nil
		for f := range reqCh {
			if err := sess.Send(context.Background(), TypeRESP, 0, f.CorrID, f.Payload); err != nil {
				srvDone <- err
				return
			}
		}
	}()

	d := &Dialer{
		Mode: "dtls", RemoteAddr: l.Addr().String(),
		PSK: psk, PSKIdentity: []byte("echo"), Timeout: 5 * time.Second,
	}
	sess := NewClientSession(d, 65536, 1200, nil)
	defer sess.Close()
	if err := sess.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	respCh, cancel := sess.Subscribe(TypeRESP)
	defer cancel()

	payload := []byte("hello-echo")
	err = sess.Send(context.Background(), TypeREQ, 0, 42, payload)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case f := <-respCh:
		if string(f.Payload) != string(payload) {
			t.Fatalf("echo mismatch: %q", f.Payload)
		}
		if f.CorrID != 42 {
			t.Fatalf("corrID=%d want 42", f.CorrID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo response timeout")
	}
	<-srvDone
}

// TestSessionFragmentedEcho echoes a payload larger than the chunk size.
func TestSessionFragmentedEcho(t *testing.T) {
	psk := []byte("frag-psk")
	l, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "dtls", PSK: psk, PSKIdentity: []byte("frag")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		sess := NewServerSession(conn, 65536, 1200, nil)
		defer sess.Close()
		reqCh, cancel := sess.Subscribe(TypeREQ)
		defer cancel()
		for f := range reqCh {
			_ = sess.Send(context.Background(), TypeRESP, 0, f.CorrID, f.Payload)
		}
	}()

	d := &Dialer{
		Mode: "dtls", RemoteAddr: l.Addr().String(),
		PSK: psk, PSKIdentity: []byte("frag"), Timeout: 5 * time.Second,
	}
	sess := NewClientSession(d, 65536, 1200, nil)
	defer sess.Close()
	if err := sess.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	respCh, cancel := sess.Subscribe(TypeRESP)
	defer cancel()

	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := sess.Send(context.Background(), TypeREQ, 0, 7, payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case f := <-respCh:
		if string(f.Payload) != string(payload) {
			t.Fatalf("fragmented echo mismatch: got %d bytes want %d", len(f.Payload), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fragmented echo timeout")
	}
}

// TestTuningDefaults pins the removal of the legacy "0 = old behaviour"
// branch: an untuned session must still get dead-peer detection, with the
// same values the config defaults produce (keepalive 10s → 30s deadline,
// 30s backoff cap). Before this, 0 meant a 90s deadline and a 5s cap, so the
// zero value silently bought the worse behaviour.
func TestTuningDefaults(t *testing.T) {
	s := &Session{}
	if got, want := s.readDeadline(), defaultKeepalive*deadlinePerKeepalive; got != want {
		t.Errorf("untuned readDeadline = %v, want %v", got, want)
	}
	if got, want := s.backoffCap(), defaultMaxBackoff; got != want {
		t.Errorf("untuned backoffCap = %v, want %v", got, want)
	}

	// Explicit tuning still wins.
	s.SetTuning(2*time.Second, time.Second)
	if got, want := s.readDeadline(), 6*time.Second; got != want {
		t.Errorf("tuned readDeadline = %v, want %v", got, want)
	}
	if got, want := s.backoffCap(), time.Second; got != want {
		t.Errorf("tuned backoffCap = %v, want %v", got, want)
	}

	// A partial tune (server sessions pass 0 for the unused backoff) falls
	// back per-field rather than to the whole legacy set.
	s.SetTuning(2*time.Second, 0)
	if got, want := s.backoffCap(), defaultMaxBackoff; got != want {
		t.Errorf("partial-tune backoffCap = %v, want %v", got, want)
	}
}
