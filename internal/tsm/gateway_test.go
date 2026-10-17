// gateway_test.go (package tsm_test): end-to-end tests for the single-box
// TSM gateway. A real DTLS client dials the gateway's raw front leg with a
// client certificate (the handshake is the authentication, RFC 5591/6353);
// TSM v3 requests (secModel=4, empty securityParameters) are relayed as
// clear v2c to a fake legacy agent and the response comes back as a TSM v3
// message on the same session. A fake TSM trap receiver validates the
// wrapped notifications on the sink direction.
package tsm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tsm"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// --- throwaway PKI (real PEM files on disk) ---------------------------------

// certFiles generates a throwaway CA plus server/client certificates into a
// temp dir and returns the PEM paths {ca, server.crt, server.key, client.crt,
// client.key}. EC P-256 keeps generation fast.
func certFiles(t *testing.T) (ca, serverCrt, serverKey, clientCrt, clientKey string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// leaf cert factory: signed by the throwaway CA
	leaf := func(cn string, serial int64) (derBytes []byte, keyPEM []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{cn},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kr, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kr})
		return der, keyPEM
	}

	serverDER, serverKeyPEM := leaf("127.0.0.1", 2)
	clientDER, clientKeyPEM := leaf("snmp-proxy-manager", 3)

	write := func(name string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	writeKey := func(name string, pemBytes []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	caPath := write("ca.pem", caDER)
	serverCrtPath := write("server.crt", serverDER)
	serverKeyPath := writeKey("server.key", serverKeyPEM)
	clientCrtPath := write("client.crt", clientDER)
	clientKeyPath := writeKey("client.key", clientKeyPEM)
	return caPath, serverCrtPath, serverKeyPath, clientCrtPath, clientKeyPath
}

// --- gateway harness ----------------------------------------------------------

// buildTSMGateway starts a TSMGateway with a raw DTLS front leg relaying to a
// fake legacy agent; the trap listener/sink are enabled when set. Returns the
// front address and a stop func.
func buildTSMGateway(t *testing.T, ca, serverCrt, serverKey string, agentAddr string, identities []string, trapListen, trapSink string) (front string, stop func()) {
	t.Helper()

	front = freeUDPPort(t)
	cfg := config.GatewayRole{
		ListenAddr:     front,
		AgentAddr:      agentAddr,
		TrapListenAddr: trapListen,
		TrapSinkAddr:   trapSink,
		AgentCommunity: "realcomm",
	}
	sec := config.Security{Mode: "tsm-gateway", TSMIdentities: identities}
	lcfg := tunnel.ListenerConfig{Mode: "dtls", CAFile: ca, CertFile: serverCrt, KeyFile: serverKey}

	gw, err := tsm.NewTSMGateway(cfg, sec, lcfg, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = gw.Run(done) }()
	return front, func() { close(done) }
}

// dialFront dials the gateway front leg with the client certificate.
func dialFront(t *testing.T, front, ca, clientCrt, clientKey string) net.Conn {
	t.Helper()
	d := &tunnel.Dialer{
		Mode:     "dtls",
		CAFile:   ca,
		CertFile: clientCrt,
		KeyFile:  clientKey,
		Timeout:  5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx, front)
	if err != nil {
		t.Fatalf("dtls dial: %v", err)
	}
	return conn
}

// buildTSMGet builds a TSM v3 GET request (secModel=4, empty security
// parameters, Reportable flag) for sysDescr.0.
func buildTSMGet(t *testing.T, msgID, reqID int32) []byte {
	t.Helper()
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0, buildGetVarbinds(t))
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      msgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// waitFrontBound blocks until the raw DTLS front leg is bound (probe via
// short-lived dtls dials would be heavy; instead poll the UDP port with a
// ListenUDP probe — the listener holds it bound at once).
func waitFrontBound(t *testing.T, front string) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", front)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.ListenUDP("udp", raddr)
		if err != nil {
			return // bound by the gateway
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s to be bound", front)
}

// --- tests ----------------------------------------------------------------------

// TestTSMGatewayGet: a TSM manager (DTLS client cert CN in the allow-list)
// sends a TSM v3 GET; the gateway relays it as clear v2c to the fake agent
// and returns the response as a TSM v3 GetResponse with the manager's
// original request-id on the same DTLS session.
func TestTSMGatewayGet(t *testing.T) {
	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)

	fake, agentAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	front, stop := buildTSMGateway(t, ca, serverCrt, serverKey, agentAddr,
		[]string{"snmp-proxy-manager"}, "", "")
	defer stop()
	waitFrontBound(t, front)

	conn := dialFront(t, front, ca, clientCrt, clientKey)
	defer conn.Close()

	if _, err := conn.Write(buildTSMGet(t, 1001, 4242)); err != nil {
		t.Fatalf("write TSM GET: %v", err)
	}

	buf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no TSM response: %v", err)
	}
	m, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("bad response datagram: %v", err)
	}
	if m.Header.SecModel != msg.SecurityModelTSM {
		t.Fatalf("response SecModel = %d, want TSM (%d)", m.Header.SecModel, msg.SecurityModelTSM)
	}
	if m.IsEncrypted() {
		t.Fatal("TSM scopedPDU must not be encrypted")
	}
	// ParseV3 pre-splits the plaintext scopedPDU into m.PDU (raw PDU TLV).
	pdu := m.PDU
	if len(pdu) == 0 || pdu[0] != msg.PDUGetResponse {
		t.Fatalf("response PDU type = %v, want GetResponse", pdu)
	}
	_, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if fields.ReqID != 4242 {
		t.Fatalf("response reqID = %d, want the client's 4242", fields.ReqID)
	}
}

// TestTSMGatewayWrongIdentity: the DTLS handshake succeeds with a valid
// certificate, but a client certificate CN outside the allow-list gets no
// response — nothing is forwarded to the legacy agent.
func TestTSMGatewayWrongIdentity(t *testing.T) {
	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)

	fake, agentAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	// allow-list deliberately excludes the client CN snmp-proxy-manager
	front, stop := buildTSMGateway(t, ca, serverCrt, serverKey, agentAddr,
		[]string{"some-other-identity"}, "", "")
	defer stop()
	waitFrontBound(t, front)

	conn := dialFront(t, front, ca, clientCrt, clientKey)
	defer conn.Close()

	if _, err := conn.Write(buildTSMGet(t, 1002, 4242)); err != nil {
		t.Fatalf("write TSM GET: %v", err)
	}

	buf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("expected silence for non-allowed identity, got %d bytes", n)
	}
}

// TestTSMGatewayTrapDirection: a legacy device fires a clear v1 trap at the
// gateway's trap listener; the gateway wraps it into a TSM v3 notification
// (secModel=4) and delivers it over a DTLS session to the manager's TSM trap
// receiver — validated here by a fake sink with its own DTLS listener.
func TestTSMGatewayTrapDirection(t *testing.T) {
	ca, serverCrt, serverKey, _, _ := certFiles(t)

	// fake TSM trap receiver: a DTLS listener that reads one record
	sink := tunnelListenRaw(t, ca, serverCrt, serverKey)
	sinkAddr := sink.Addr().String()
	sinkGot := make(chan []byte, 1)
	go func() {
		c, err := sink.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 65536)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(buf)
		if err == nil {
			sinkGot <- append([]byte(nil), buf[:n]...)
		}
	}()

	trapListen := freeUDPPort(t)
	fake, agentAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	_, stop := buildTSMGateway(t, ca, serverCrt, serverKey, agentAddr,
		[]string{"snmp-proxy-manager"}, trapListen, sinkAddr)
	defer stop()
	waitFrontBound(t, trapListen)

	// device fires a clear v1 coldStart trap at the gateway's trap listener
	trapPDU := msg.BuildV1Trap(msg.V1Trap{
		Enterprise: mustOID(t, "1.3.6.1.4.1.9999"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    0, // coldStart
		Specific:   0,
		Timestamp:  12345,
		Varbinds:   []byte{},
	})
	trap, err := msg.BuildV1V2c(msg.Version1, []byte("devicecomm"), trapPDU)
	if err != nil {
		t.Fatal(err)
	}
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(trap, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-sinkGot:
		m, err := msg.ParseV3(got)
		if err != nil {
			t.Fatalf("bad sink datagram: %v", err)
		}
		if m.Header.SecModel != msg.SecurityModelTSM {
			t.Fatalf("sink SecModel = %d, want TSM (%d)", m.Header.SecModel, msg.SecurityModelTSM)
		}
		if m.IsEncrypted() {
			t.Fatal("TSM scopedPDU must not be encrypted")
		}
		// ParseV3 pre-splits the plaintext scopedPDU into m.PDU.
		pdu := m.PDU
		if len(pdu) == 0 || pdu[0] != msg.PDUSNMPv2Trap {
			t.Fatalf("sink PDU = %v, want SNMPv2-Trap", pdu)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped TSM trap never reached the sink")
	}
}

// tunnelListenRaw starts a raw DTLS listener for use as a fake trap sink.
func tunnelListenRaw(t *testing.T, ca, crt, key string) net.Listener {
	t.Helper()
	l, err := tunnel.ListenRaw("127.0.0.1:0", tunnel.ListenerConfig{
		Mode: "dtls", CAFile: ca, CertFile: crt, KeyFile: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}
