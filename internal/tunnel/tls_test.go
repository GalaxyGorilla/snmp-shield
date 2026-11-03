// Direct tests for the TLS/TCP transport and the certificate mode of the
// DTLS transport.
//
// The cross-package conformance suite drives TLS through the built binary,
// but this package's own profile only sees its own tests — so a break in
// tlsConfig, tlsServerConfig, ListenRaw or the peer-certificate extraction
// would not show up in the package coverage gate or in the unit race suite.
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// startTLSPair runs one mTLS listener and returns the server session and a
// connected client session. The server requires a client certificate.
func startTLSPair(t *testing.T, srv ListenerConfig, dialer *Dialer) (*Session, *Session) {
	t.Helper()
	l, err := Listen("127.0.0.1:0", srv)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	accCh := make(chan *Session, 1)
	accErr := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accErr <- err
			return
		}
		accCh <- NewServerSession(c, 65536, 1200, nil)
	}()

	dialer.RemoteAddr = l.Addr().String()
	client := NewClientSession(dialer, 65536, 1200, nil)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	select {
	case srvSess := <-accCh:
		t.Cleanup(func() { _ = srvSess.Close() })
		return srvSess, client
	case err := <-accErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("accept timeout")
	}
	return nil, nil
}

func waitPeerCert(t *testing.T, s *Session, what string) []*x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if certs := s.PeerCerts(); len(certs) > 0 {
			return certs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: no peer certificate after the handshake", what)
	return nil
}

func TestTLSCertificateHandshakeAndPeerCerts(t *testing.T) {
	pki := newTestPKI(t)
	srvCfg := ListenerConfig{
		Mode: "tls", CAFile: pki.CAFile,
		CertFile: pki.ServerCrt, KeyFile: pki.ServerKey,
	}
	srv, cli := startTLSPair(t, srvCfg, &Dialer{
		Mode: "tls", CAFile: pki.CAFile,
		CertFile: pki.ClientCrt, KeyFile: pki.ClientKey,
		ServerName: "localhost", Timeout: 5 * time.Second,
	})

	clientSees := waitPeerCert(t, cli, "client")
	if clientSees[0].Subject.CommonName != "snmp-shield-server" {
		t.Fatalf("client peer cert CN = %q, want snmp-shield-server", clientSees[0].Subject.CommonName)
	}
	serverSees := waitPeerCert(t, srv, "server")
	if serverSees[0].Subject.CommonName != "snmp-shield-manager" {
		t.Fatalf("server peer cert CN = %q, want snmp-shield-manager", serverSees[0].Subject.CommonName)
	}
}

func TestTLSCertificateModeRejectsClientWithoutCert(t *testing.T) {
	pki := newTestPKI(t)
	srvCfg := ListenerConfig{
		Mode: "tls", CAFile: pki.CAFile,
		CertFile: pki.ServerCrt, KeyFile: pki.ServerKey,
	}
	l, err := Listen("127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	serveRejected(t, l)

	// Trusts the server but presents no client certificate.
	d := &Dialer{
		Mode: "tls", RemoteAddr: l.Addr().String(), CAFile: pki.CAFile,
		ServerName: "localhost", Timeout: 3 * time.Second,
	}
	expectRejected(t, d, "server requiring a client certificate accepted a client without one")
}

// serveRejected accepts one connection and runs the real server session so
// the handshake actually executes. Without the read loop, a rejected client
// would only fail on its own timeout, which would make the test pass for the
// wrong reason.
func serveRejected(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		s := NewServerSession(c, 65536, 1200, nil)
		<-s.Done()
		_ = s.Close()
	}()
}

// expectRejected asserts that a single transport dial either fails outright
// or yields a connection the peer drops promptly.
//
// A Session is deliberately not used here: it retries with backoff by
// design, so a rejected handshake would only surface as a context deadline
// (and a server-side TLS 1.3 rejection can arrive after the client's
// handshake returns). One raw dial plus a probe read distinguishes "refused"
// from "accepted and idle".
func expectRejected(t *testing.T, d *Dialer, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := d.Dial(ctx, d.RemoteAddr)
	if err != nil {
		if elapsed := time.Since(start); elapsed > 6*time.Second {
			t.Fatalf("%s (only after the %s timeout: %v)", msg, elapsed.Round(time.Millisecond), err)
		}
		return
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := conn.Write([]byte("probe")); err != nil {
		return // the peer already closed it
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("%s (peer sent data on a rejected connection)", msg)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s (connection stayed usable)", msg)
	}
}

func TestTLSCertificateModeRejectsUntrustedCA(t *testing.T) {
	serverPKI := newTestPKI(t)
	clientPKI := newTestPKI(t)
	srvCfg := ListenerConfig{
		Mode: "tls", CAFile: serverPKI.CAFile,
		CertFile: serverPKI.ServerCrt, KeyFile: serverPKI.ServerKey,
	}
	l, err := Listen("127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	serveRejected(t, l)

	// The client trusts a different CA than the one that signed the server.
	d := &Dialer{
		Mode: "tls", RemoteAddr: l.Addr().String(), CAFile: clientPKI.CAFile,
		CertFile: clientPKI.ClientCrt, KeyFile: clientPKI.ClientKey,
		ServerName: "localhost", Timeout: 3 * time.Second,
	}
	expectRejected(t, d, "client trusted an unrelated CA and still completed the handshake")
}

func TestDTLSCertificateModeAndPeerCerts(t *testing.T) {
	pki := newTestPKI(t)
	srvCfg := ListenerConfig{
		Mode: "dtls", CAFile: pki.CAFile,
		CertFile: pki.ServerCrt, KeyFile: pki.ServerKey,
	}
	l, err := Listen("127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	accCh := make(chan *Session, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		accCh <- NewServerSession(c, 65536, 1200, nil)
	}()

	d := &Dialer{
		Mode: "dtls", RemoteAddr: l.Addr().String(), CAFile: pki.CAFile,
		CertFile: pki.ClientCrt, KeyFile: pki.ClientKey,
		ServerName: "localhost", Timeout: 5 * time.Second,
	}
	cli := NewClientSession(d, 65536, 1200, nil)
	t.Cleanup(func() { _ = cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cli.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	select {
	case srv := <-accCh:
		t.Cleanup(func() { _ = srv.Close() })
		// streamConn.peerCerts decodes pion's DER chain; both sides must
		// expose the other's certificate for TSM identity mapping.
		if got := waitPeerCert(t, cli, "dtls client"); got[0].Subject.CommonName != "snmp-shield-server" {
			t.Fatalf("client peer cert CN = %q", got[0].Subject.CommonName)
		}
		if got := waitPeerCert(t, srv, "dtls server"); got[0].Subject.CommonName != "snmp-shield-manager" {
			t.Fatalf("server peer cert CN = %q", got[0].Subject.CommonName)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dtls accept timeout")
	}
}

func TestTLSConfigErrors(t *testing.T) {
	pki := newTestPKI(t)
	cases := []struct {
		name string
		cfg  ListenerConfig
	}{
		{"missing cert and key", ListenerConfig{Mode: "tls"}},
		{"missing key", ListenerConfig{Mode: "tls", CertFile: pki.ServerCrt}},
		{"missing cert file", ListenerConfig{Mode: "tls", CertFile: "/nonexistent/c.pem", KeyFile: pki.ServerKey}},
		{"missing CA file", ListenerConfig{Mode: "tls", CertFile: pki.ServerCrt, KeyFile: pki.ServerKey, CAFile: "/nonexistent/ca.pem"}},
		{"CA with no certificates", ListenerConfig{Mode: "tls", CertFile: pki.ServerCrt, KeyFile: pki.ServerKey, CAFile: pki.ServerKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tlsServerConfig(tc.cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDialerTLSConfigErrors(t *testing.T) {
	pki := newTestPKI(t)
	cases := []struct {
		name string
		d    *Dialer
	}{
		{"no identity", &Dialer{Mode: "tls"}},
		{"missing client cert file", &Dialer{Mode: "tls", CertFile: "/nonexistent/c.pem", KeyFile: pki.ClientKey, Insecure: true}},
		{"missing CA file", &Dialer{Mode: "tls", CAFile: "/nonexistent/ca.pem"}},
		{"CA with no certificates", &Dialer{Mode: "tls", CAFile: pki.ClientKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.d.tlsConfig(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// Explicit opt-outs are accepted: insecure, or a server name with no CA
	// (system roots), or a CA with no server name.
	for _, d := range []*Dialer{
		{Mode: "tls", Insecure: true},
		{Mode: "tls", ServerName: "localhost"},
		{Mode: "tls", CAFile: pki.CAFile},
	} {
		cfg, err := d.tlsConfig()
		if err != nil {
			t.Fatalf("tlsConfig(%+v): %v", d, err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
		}
	}
}

func TestListenErrorPaths(t *testing.T) {
	if _, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "bogus"}); err == nil {
		t.Fatal("unknown tunnel mode accepted")
	}
	if _, err := ListenRaw("127.0.0.1:0", ListenerConfig{Mode: "tls"}); err == nil {
		t.Fatal("raw TLS accepted; TCP has no record boundaries")
	}
	if _, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "dtls"}); err == nil {
		t.Fatal("dtls without PSK or certificates accepted")
	}
	if _, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "dtls", PSK: []byte("x"), PskCiphersuites: []string{"bogus"}}); err == nil {
		t.Fatal("unknown PSK cipher suite accepted")
	}
	if _, err := ListenRaw("127.0.0.1:0", ListenerConfig{Mode: "dtls", PSK: []byte("x"), PskCiphersuites: []string{"bogus"}}); err == nil {
		t.Fatal("unknown PSK cipher suite accepted in raw mode")
	}
}

func TestStreamListenerAcceptAfterClose(t *testing.T) {
	l, err := Listen("127.0.0.1:0", ListenerConfig{Mode: "dtls", PSK: []byte("x")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = l.Close()
	if c, err := l.Accept(); err == nil {
		_ = c.Close()
		t.Fatal("Accept on a closed listener returned a connection")
	}
}

func TestStreamConnPeerCertsWithoutHandshake(t *testing.T) {
	// A streamConn wrapping a non-(D)TLS conn has no peer chain; it must
	// return nil rather than panic.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sc := &streamConn{conn: a}
	if got := sc.PeerCerts(); got != nil {
		t.Fatalf("PeerCerts on a plain pipe = %v, want nil", got)
	}
	// Exercise the net.Conn delegation too: net.Pipe addresses are opaque,
	// so only the call itself is asserted.
	_ = sc.LocalAddr()
	_ = sc.RemoteAddr()
	_ = sc.SetDeadline(time.Now().Add(time.Second))
}
