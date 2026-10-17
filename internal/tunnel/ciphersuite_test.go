package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

func TestPskCiphersuiteNames(t *testing.T) {
	names := PskCiphersuiteNames()
	want := 5
	if len(names) != want {
		t.Fatalf("got %d names, want %d: %v", len(names), want, names)
	}
	for _, n := range names {
		if n == "" {
			t.Fatalf("empty name in %v", names)
		}
	}
}

func TestPskCipherSuiteIDsDefault(t *testing.T) {
	ids, err := PskCipherSuiteIDs(nil)
	if err != nil {
		t.Fatalf("nil list: %v", err)
	}
	if len(ids) != 1 || ids[0] != dtls.TLS_PSK_WITH_AES_128_CCM_8 {
		t.Errorf("default = %v, want [TLS_PSK_WITH_AES_128_CCM_8]", ids)
	}
	ids, err = PskCipherSuiteIDs([]string{""})
	if err != nil {
		t.Fatalf("blank-only list: %v", err)
	}
	if len(ids) != 1 || ids[0] != dtls.TLS_PSK_WITH_AES_128_CCM_8 {
		t.Errorf("blank-only default = %v", ids)
	}
}

func TestPskCipherSuiteIDsResolve(t *testing.T) {
	// Order must be preserved (client preference order).
	ids, err := PskCipherSuiteIDs([]string{"aes256-ccm-8", "aes128-gcm"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ids) != 2 || ids[0] != dtls.TLS_PSK_WITH_AES_256_CCM_8 || ids[1] != dtls.TLS_PSK_WITH_AES_128_GCM_SHA256 {
		t.Errorf("resolved = %v", ids)
	}
	// Full RFC name aliases.
	ids, err = PskCipherSuiteIDs([]string{"TLS_PSK_WITH_AES_256_CCM_8"})
	if err != nil {
		t.Fatalf("rfc alias: %v", err)
	}
	if len(ids) != 1 || ids[0] != dtls.TLS_PSK_WITH_AES_256_CCM_8 {
		t.Errorf("rfc alias resolved = %v", ids)
	}
	// Whitespace and blanks are tolerated.
	ids, err = PskCipherSuiteIDs([]string{" aes128-cbc ", "", "aes128-ccm"})
	if err != nil {
		t.Fatalf("whitespace: %v", err)
	}
	if len(ids) != 2 || ids[0] != dtls.TLS_PSK_WITH_AES_128_CBC_SHA256 || ids[1] != dtls.TLS_PSK_WITH_AES_128_CCM {
		t.Errorf("whitespace resolved = %v", ids)
	}
}

func TestPskCipherSuiteIDsUnknown(t *testing.T) {
	if _, err := PskCipherSuiteIDs([]string{"aes128-ccm-8", "chacha20-poly1305"}); err == nil {
		t.Error("unknown suite accepted")
	}
	if err := ValidatePskCiphersuites(nil); err != nil {
		t.Errorf("validate empty: %v", err)
	}
	if err := ValidatePskCiphersuites([]string{"bogus"}); err == nil {
		t.Error("validate accepted bogus suite")
	}
}

// TestPskHandshakePerCiphersuite drives a real PSK-DTLS handshake
// through the session layer for every supported suite, plus a
// multi-suite preference list.
func TestPskHandshakePerCiphersuite(t *testing.T) {
	cases := []struct {
		name   string
		suites []string
	}{
		{"default (empty)", nil},
		{"aes128-ccm-8", []string{"aes128-ccm-8"}},
		{"aes256-ccm-8", []string{"aes256-ccm-8"}},
		{"aes128-ccm", []string{"aes128-ccm"}},
		{"aes128-gcm", []string{"aes128-gcm"}},
		{"aes128-cbc", []string{"aes128-cbc"}},
		{"rfc alias", []string{"TLS_PSK_WITH_AES_256_CCM_8"}},
		{"multi preference", []string{"aes256-ccm-8", "aes128-gcm", "aes128-ccm-8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			psk := []byte("suite-test-psk")
			l, err := Listen("127.0.0.1:0", ListenerConfig{
				Mode: "dtls", PSK: psk, PSKIdentity: []byte("suite"),
				PskCiphersuites: tc.suites,
			})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer l.Close()

			accCh := make(chan error, 1)
			go func() {
				c, aerr := l.Accept()
				if aerr != nil {
					accCh <- aerr
					return
				}
				// Serve the conn like the real proxy: the server-side
				// handshake only starts once Read/Write is called.
				srvSess := NewServerSession(c, 65536, 1200, nil)
				defer srvSess.Close()
				accCh <- nil
				<-srvSess.readStop
			}()

			d := &Dialer{
				Mode:            "dtls",
				RemoteAddr:      l.Addr().String(),
				PSK:             psk,
				PSKIdentity:     []byte("suite"),
				PskCiphersuites: tc.suites,
				Timeout:         5 * time.Second,
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
		})
	}
}

// TestPskCiphersuiteMismatchRejected verifies that a client whose
// cipher suite list does not overlap the server's fails the handshake
// instead of silently connecting.
func TestPskCiphersuiteMismatchRejected(t *testing.T) {
	psk := []byte("mismatch-psk")
	l, err := Listen("127.0.0.1:0", ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("mis"),
		PskCiphersuites: []string{"aes128-gcm"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	// Serve EVERY accepted conn like the real proxy: the client session
	// reconnects with a fresh UDP port after the failed handshake, and
	// pion's listener creates a new accepted conn per remote address —
	// an unserved conn would leave the client's lazy handshake waiting
	// forever (pion's server handshake only starts on first Read/Write).
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			// Serve the conn; the handshake will fail inside.
			srvSess := NewServerSession(c, 65536, 1200, nil)
			go func() {
				defer srvSess.Close()
				<-srvSess.readStop
			}()
		}
	}()

	d := &Dialer{
		Mode:            "dtls",
		RemoteAddr:      l.Addr().String(),
		PSK:             psk,
		PSKIdentity:     []byte("mis"),
		PskCiphersuites: []string{"aes128-cbc"},
		Timeout:         3 * time.Second,
	}
	sess := NewClientSession(d, 65536, 1200, nil)
	defer sess.Close()

	// The server's fatal alert arrives in milliseconds; the client then
	// backoff-retries until the context expires — which is the expected
	// failed-connect outcome.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sess.Connect(ctx); err == nil {
		t.Fatal("mismatched cipher suites connected; want handshake failure")
	}
}
