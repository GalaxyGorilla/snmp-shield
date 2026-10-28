package proxy

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/snmpmetrics"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/gosnmp/gosnmp"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// --- test helpers ---------------------------------------------------------------

// freeUDPPort returns a free 127.0.0.1 UDP address (bound then released).
func freeUDPPort(t *testing.T) string {
	t.Helper()
	return freeUDPPortOn(t, "127.0.0.1")
}

// freeUDPPortOn is freeUDPPort for an explicit host, so a scenario can put a
// deployment leg on ::1.
func freeUDPPortOn(t *testing.T, host string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("free udp port on %s: %v", host, err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

// waitBound blocks until addr is bound by someone else (our probe bind
// fails) — removes the startup race against the runX loops.
func waitBound(t *testing.T, addr string) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.ListenUDP("udp", raddr)
		if err != nil {
			return // already bound
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s to be bound", addr)
}

// fakeAgent is a fake v2c agent echoing GET requests (req-id and varbinds).
func fakeAgent(t *testing.T, addr string) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			dg := append([]byte(nil), buf[:n]...)
			ver, community, pdu, err := msg.SplitV1V2c(dg)
			if err != nil {
				continue
			}
			_, fields, err := msg.ParsePDU(pdu)
			if err != nil {
				continue
			}
			resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
			out, err := msg.BuildV1V2c(ver, community, resp)
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(out, from)
		}
	}()
	return conn
}

// countingFakeAgent is fakeAgent plus a counter of every SET that reaches
// it — the oracle for "the device never saw the write".
func countingFakeAgent(t *testing.T, addr string) (net.PacketConn, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var sets atomic.Int32
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			dg := append([]byte(nil), buf[:n]...)
			ver, community, pdu, serr := msg.SplitV1V2c(dg)
			if serr != nil {
				continue
			}
			if info, ierr := msg.Peek(dg); ierr == nil && msg.IsSet(info.PDUType) {
				sets.Add(1)
			}
			_, fields, perr := msg.ParsePDU(pdu)
			if perr != nil {
				continue
			}
			resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
			out, berr := msg.BuildV1V2c(ver, community, resp)
			if berr != nil {
				continue
			}
			_, _ = conn.WriteTo(out, from)
		}
	}()
	return conn, &sets
}

// gosnmpV3 builds an authPriv (SHA/AES) gosnmp v3 client matching the
// default test user ("proxy").
func gosnmpV3(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	g := &gosnmp.GoSNMP{
		Target:        h,
		Port:          uint16(port),
		Version:       gosnmp.Version3,
		Timeout:       3 * time.Second,
		Retries:       2,
		MaxOids:       10,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "proxy",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        "privpass",
		},
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("gosnmp connect: %v", err)
	}
	return g
}

// gosnmpV2c builds a plain v2c gosnmp client.
func gosnmpV2c(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	g := &gosnmp.GoSNMP{
		Target:    h,
		Port:      uint16(port),
		Version:   gosnmp.Version2c,
		Timeout:   3 * time.Second,
		Retries:   2,
		MaxOids:   10,
		Community: "public",
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("gosnmp connect: %v", err)
	}
	return g
}

// startAgent runs runAgent in the background with a cancelable context.
func startAgent(t *testing.T, cfg *config.Config, met *observ.Metrics, holders ...*access.Holder) (cancel context.CancelFunc, errCh chan error) {
	t.Helper()
	var h *access.Holder
	if len(holders) > 0 {
		h = holders[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh = make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		errCh <- runAgent(ctx, Options{Config: cfg, Log: zap.NewNop(), Version: "test", Access: h}, met, nil, ready)
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent exited during startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for agent startup")
	}
	return cancel, errCh
}

// startManager runs runManager in the background with a cancelable context.
func startManager(t *testing.T, cfg *config.Config, met *observ.Metrics) (cancel context.CancelFunc, errCh chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh = make(chan error, 1)
	go func() { errCh <- runManager(ctx, Options{Config: cfg, Log: zap.NewNop(), Version: "test"}, met, nil) }()
	waitBound(t, cfg.Manager.ListenAddr)
	return cancel, errCh
}

// startGateway runs runGateway in the background with a cancelable context.
func startGateway(t *testing.T, cfg *config.Config, met *observ.Metrics) (cancel context.CancelFunc, errCh chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh = make(chan error, 1)
	go func() { errCh <- runGateway(ctx, Options{Config: cfg, Log: zap.NewNop()}, met) }()
	waitBound(t, cfg.Gateway.ListenAddr)
	return cancel, errCh
}

// stopRun cancels a background runX and asserts it shut down cleanly.
func stopRun(t *testing.T, cancel context.CancelFunc, errCh chan error, name string) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("%s: run returned %v", name, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: run did not shut down within 5s", name)
	}
}

// testUsers is a valid USM user set (ProfilesFromSecurity silently skips
// users with invalid protocols, so all fields must be valid).
func testUsers() []config.UserCfg {
	return []config.UserCfg{{
		Name:           "proxy",
		AuthProtocol:   "sha",
		AuthPassphrase: "authpass",
		PrivProtocol:   "aes",
		PrivPassphrase: "privpass",
		Community:      "public",
	}}
}

// --- certFiles: throwaway PKI (mirrors tsm gateway_test) ------------------------

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
	clientDER, clientKeyPEM := leaf("snmp-shield-manager", 3)

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

	return write("ca.pem", caDER), write("server.crt", serverDER),
		writeKey("server.key", serverKeyPEM), write("client.crt", clientDER),
		writeKey("client.key", clientKeyPEM)
}

// --- e2e tests ------------------------------------------------------------------

// TestRunManagerPassthroughE2E wires a full two-proxy chain (real DTLS
// tunnel, passthrough mode) and pushes a v2c GET through it.
func TestRunManagerPassthroughE2E(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = agentAddr
	agentListen := agentCfg.Tunnel.ListenAddr

	agCancel, agErr := startAgent(t, agentCfg, met)
	defer agCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	mgrListen := mgrCfg.Manager.ListenAddr

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrListen)

	// Push a clear v2c GET through the chain.
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	mgrUDP, err := net.ResolveUDPAddr("udp", mgrListen)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 4242, 0, 0, msg.AppendTLV(nil, 0x30, msg.AppendTLV(msg.AppendTLV(nil, 0x06, oid), 0x05, nil)))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sock.WriteTo(dg, mgrUDP); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	if err := sock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response through chain: %v", err)
	}
	_, community, rpdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if string(community) != "public" {
		t.Fatalf("community = %q, want public", community)
	}
	typ, fields, err := msg.ParsePDU(rpdu)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if typ != msg.PDUGetResponse {
		t.Fatalf("response type = %#x, want GETRESPONSE", typ)
	}
	if fields.ReqID != 4242 {
		t.Fatalf("req-id = %d, want 4242 (echoed)", fields.ReqID)
	}

	stopRun(t, agCancel, agErr, "agent")
	stopRun(t, mgCancel, mgErr, "manager")
}

// TestRunManagerPassthroughIPv6 runs the whole two-proxy deployment on ::1:
// both clear legs and the DTLS tunnel between them. The tunnel dialer itself
// is family-transparent, but the deployment is not proven until the config
// addresses, the listener binds and the device socket all agree on a v6
// loopback.
func TestRunManagerPassthroughIPv6(t *testing.T) {
	if _, err := net.ListenPacket("udp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	met := observ.NewMetrics()
	agent := fakeAgent(t, "[::1]:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPortOn(t, "::1")
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = agentAddr
	agentListen := agentCfg.Tunnel.ListenAddr

	agCancel, agErr := startAgent(t, agentCfg, met)
	defer agCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPortOn(t, "::1")
	mgrListen := mgrCfg.Manager.ListenAddr

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrListen)

	sock, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	mgrUDP, err := net.ResolveUDPAddr("udp", mgrListen)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 4242, 0, 0, msg.AppendTLV(msg.AppendTLV(nil, 0x06, oid), 0x05, nil))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sock.WriteTo(dg, mgrUDP); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	if err := sock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := sock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response through the IPv6 chain: %v", err)
	}
	_, community, rpdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if string(community) != "public" {
		t.Fatalf("community = %q, want public", community)
	}
	typ, fields, err := msg.ParsePDU(rpdu)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if typ != msg.PDUGetResponse {
		t.Fatalf("response type = %#x, want GETRESPONSE", typ)
	}
	if fields.ReqID != 4242 {
		t.Fatalf("req-id = %d, want 4242 (echoed)", fields.ReqID)
	}

	stopRun(t, agCancel, agErr, "agent")
	stopRun(t, mgCancel, mgErr, "manager")
}

// TestRunManagerUSME2E wires the two-proxy chain in usm-translate mode.
// The manager's clear leg still speaks v1/v2c (USM security rides the
// tunnel), so a v2c client drives the full chain end to end; the
// translation path itself is covered by the usm package tests.
func TestRunManagerUSME2E(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = agentAddr
	agentCfg.Security.Mode = "usm-translate"
	agentCfg.Security.Users = testUsers()
	agentCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	agentListen := agentCfg.Tunnel.ListenAddr

	agCancel, agErr := startAgent(t, agentCfg, met)
	defer agCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	mgrCfg.Security.Mode = "usm-translate"
	mgrCfg.Security.Users = testUsers()
	mgrCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	mgrListen := mgrCfg.Manager.ListenAddr

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrListen)

	g := gosnmpV2c(t, mgrListen)
	defer g.Conn.Close()
	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("v2c GET through chain: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("variables = %d, want 1", len(result.Variables))
	}
	// gosnmp prepends a leading dot to returned OIDs.
	if result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("oid = %q", result.Variables[0].Name)
	}

	stopRun(t, agCancel, agErr, "agent")
	stopRun(t, mgCancel, mgErr, "manager")
}

// TestRunGatewayUSM wires the single-box USM gateway and drives it with a
// real gosnmp v3 authPriv client.
func TestRunGatewayUSM(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Tunnel.Mode = "dtls"
	cfg.Gateway.ListenAddr = freeUDPPort(t)
	cfg.Gateway.AgentAddr = agentAddr
	cfg.Security.Mode = "usm-gateway"
	cfg.Security.Users = testUsers()
	cfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")

	cancel, errCh := startGateway(t, cfg, met)
	defer cancel()

	g := gosnmpV3(t, cfg.Gateway.ListenAddr)
	defer g.Conn.Close()
	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("v3 GET through gateway: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("variables = %d, want 1", len(result.Variables))
	}
	if result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("oid = %q", result.Variables[0].Name)
	}

	stopRun(t, cancel, errCh, "gateway")
}

// TestRunGatewayTSM wires the single-box TSM gateway (raw DTLS front leg,
// RFC 6353) and drives it with a cert-authenticated DTLS client.
func TestRunGatewayTSM(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)

	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Gateway.ListenAddr = freeUDPPort(t)
	cfg.Gateway.AgentAddr = agentAddr
	cfg.Security.Mode = "tsm-gateway"
	cfg.Tunnel.CAFile = ca
	cfg.Tunnel.CertFile = serverCrt
	cfg.Tunnel.KeyFile = serverKey

	cancel, errCh := startGateway(t, cfg, met)
	defer cancel()

	// DTLS client presenting the trusted client cert (tunnel.Dialer runs
	// the handshake eagerly and wraps DTLS properly for UDP).
	d := &tunnel.Dialer{
		Mode:     "dtls",
		CAFile:   ca,
		CertFile: clientCrt,
		KeyFile:  clientKey,
		Timeout:  10 * time.Second,
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	dconn, err := d.Dial(dctx, cfg.Gateway.ListenAddr)
	if err != nil {
		t.Fatalf("dtls dial: %v", err)
	}
	defer dconn.Close()

	// TSM v3 GET: plaintext scopedPDU, empty secParams (RFC 5591).
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 777, 0, 0, msg.AppendTLV(nil, 0x30, msg.AppendTLV(msg.AppendTLV(nil, 0x06, oid), 0x05, nil)))
	scoped := msg.BuildScoped(nil, nil, pdu)
	dg, err := msg.BuildV3(msg.V3Header{
		MsgID:      1234,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   0,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dconn.Write(dg); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	if err := dconn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := dconn.Read(buf)
	if err != nil {
		t.Fatalf("no TSM response: %v", err)
	}
	m2, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("bad TSM response: %v", err)
	}
	if m2.Header.MsgID != 1234 {
		t.Fatalf("msgID = %d, want 1234 (echoed)", m2.Header.MsgID)
	}
	typ, fields, err := msg.ParsePDU(m2.PDU)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if typ != msg.PDUGetResponse {
		t.Fatalf("response type = %#x, want GETRESPONSE", typ)
	}
	if fields.ReqID != 777 {
		t.Fatalf("req-id = %d, want 777 (echoed)", fields.ReqID)
	}

	// Close the client conn before shutdown: serveFront blocks on Read
	// until the client goes away.
	_ = dconn.Close()
	stopRun(t, cancel, errCh, "gateway")
}

// --- unit tests -----------------------------------------------------------------

func TestParseEngineID(t *testing.T) {
	if got, err := parseEngineID(""); err != nil || got != nil {
		t.Fatalf("parseEngineID(\"\") = %v, %v; want nil, nil", got, err)
	}
	got, err := parseEngineID("hex:8000")
	if err != nil || string(got) != "\x80\x00" {
		t.Fatalf("parseEngineID(hex:8000) = %v, %v", got, err)
	}
	got, err = parseEngineID("8000")
	if err != nil || string(got) != "\x80\x00" {
		t.Fatalf("parseEngineID(8000) = %v, %v", got, err)
	}
	if _, err := parseEngineID("zz"); err == nil {
		t.Fatal("parseEngineID(zz) = nil error, want invalid-hex error")
	}
}

// TestSNMPMetricsE2E wires a full two-proxy chain with the SNMP health
// agent enabled on the manager side (MIB listener + trap sink) and
// verifies both delivery paths over real sockets: health polling with
// v2c GET (identity scalars, tunnelUp) and a tunnel-lifecycle trap
// (tunnel down → trap at the sink).
func TestSNMPMetricsE2E(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = agentAddr
	agentListen := agentCfg.Tunnel.ListenAddr

	agCancel, agErrCh := startAgent(t, agentCfg, met)
	defer agCancel()

	// SNMP trap sink: a plain UDP listener collecting datagrams.
	sinkPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sinkPC.Close()
	sinkAddr := sinkPC.LocalAddr().String()
	trapCh := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := sinkPC.ReadFrom(buf)
			if err != nil {
				return
			}
			dg := make([]byte, n)
			copy(dg, buf[:n])
			trapCh <- dg
		}
	}()

	// Manager config with the SNMP metrics interface enabled.
	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	// Short keepalive so dead-peer detection drops the session quickly
	// after the agent-side listener dies (UDP gives no connection-state
	// notification; 1s keepalive → 3s read deadline × 3 misses ≈ 9s).
	mgrCfg.Tunnel.KeepaliveSecs = 1
	mgrCfg.Tunnel.MaxReconnectBackoff = 1
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	mgrCfg.Metrics = config.MetricsRole{
		ListenAddr:   freeUDPPort(t),
		Community:    "metcomm",
		TrapSinkAddr: sinkAddr,
	}
	mgrListen := mgrCfg.Manager.ListenAddr
	snmpListen := mgrCfg.Metrics.ListenAddr

	// startManager passes nil for the SNMP agent; this test needs the
	// real agent wired to the same met set, so run runManager manually
	// (same pattern as startManager) with a constructed agent.
	{
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		snmpAgent := snmpmetrics.New(snmpmetrics.Config{
			Community:  mgrCfg.Metrics.Community,
			BaseOID:    mgrCfg.Metrics.BaseOID,
			Version:    "test",
			Role:       "manager",
			SecMode:    mgrCfg.Security.Mode,
			TunnelMode: mgrCfg.Tunnel.Mode,
			Endpoints:  agentListen,
		}, met.CounterList(), met.ForwardLatency, zap.NewNop())
		stop := make(chan struct{})
		defer close(stop)
		go func() { _ = snmpAgent.Serve(snmpListen, stop) }()
		go func() {
			errCh <- runManager(ctx, Options{Config: mgrCfg, Log: zap.NewNop(), Version: "test"}, met, snmpAgent)
		}()
		defer func() {
			cancel()
			select {
			case e := <-errCh:
				if e != nil {
					t.Errorf("manager run: %v", e)
				}
			case <-time.After(5 * time.Second):
				t.Error("manager did not shut down within 5s")
			}
		}()
	}

	waitBound(t, mgrListen)
	waitBoundSnmp(t, snmpListen)

	base := "1.3.6.1.4.1.58427.1"

	// 1. Health polling: identity scalars via v2c GET.
	snmpSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer snmpSock.Close()
	snmpUDP, err := net.ResolveUDPAddr("udp", snmpListen)
	if err != nil {
		t.Fatal(err)
	}
	oidBytes, err := msg.EncodeOID(base + ".1")
	if err != nil {
		t.Fatal(err)
	}
	getPDU := msg.BuildPDU(msg.PDUGetRequest, 77, 0, 0,
		msg.AppendTLV(nil, 0x30, msg.AppendOIDTLV(nil, oidBytes)))
	getDG, err := msg.BuildV1V2c(msg.Version2c, []byte("metcomm"), getPDU)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snmpSock.WriteTo(getDG, snmpUDP); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	if err := snmpSock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := snmpSock.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no SNMP health response: %v", err)
	}
	_, _, rpdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad health response: %v", err)
	}
	typ, fields, err := msg.ParsePDU(rpdu)
	if err != nil {
		t.Fatalf("bad health response PDU: %v", err)
	}
	if typ != msg.PDUGetResponse || fields.ReqID != 77 {
		t.Fatalf("health response type 0x%02x reqID %d, want GETRESPONSE/77", typ, fields.ReqID)
	}

	// 2. Trap direction: kill the agent-side proxy (listener closes);
	// the manager's session sees PING misses (keepalive 1s → dead in
	// ~9s) and drops the tunnel — a tunnel-down trap must land at the
	// sink. After the drop the session reconnects in the background
	// (agent listener is gone; reconnect loops — that's fine, the run
	// is cancelled below).
	agCancel()
	<-agErrCh
	select {
	case dg := <-trapCh:
		validateTrap(t, dg)
	case <-time.After(25 * time.Second):
		t.Fatal("no tunnel-down trap at the sink within 25s")
	}
}

// TestSNMPMetricsDownTrap pins the trap wiring directly: a client
// session with short keepalive + SNMP agent + trap sink; killing the
// peer must produce a tunnel-down trap at the sink.
func TestSNMPMetricsDownTrap(t *testing.T) {
	lA := freeListenerDTLS(t)
	defer func() { _ = lA.Close() }()

	sinkPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sinkPC.Close()
	trapCh := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := sinkPC.ReadFrom(buf)
			if err != nil {
				return
			}
			dg := make([]byte, n)
			copy(dg, buf[:n])
			trapCh <- dg
		}
	}()

	met := observ.NewMetrics()
	snmpAgent := snmpmetrics.New(snmpmetrics.Config{
		Community: "metcomm",
		Version:   "test",
		Role:      "manager",
	}, met.CounterList(), met.ForwardLatency, zap.NewNop())

	cancel := make(chan struct{})
	defer close(cancel)
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := lA.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sess := tunnel.NewServerSession(conn, 65536, 1200, zap.NewNop())
				defer sess.Close()
				sess.SetTuning(100*time.Millisecond, 0)
				select {
				case <-sess.Done():
				case <-cancel:
				}
			}()
		}
	}()

	dial := &tunnel.Dialer{
		Mode:        "dtls",
		RemoteAddr:  lA.Addr().String(),
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
		Timeout:     2 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, 65536, 1200, zap.NewNop())
	defer sess.Close()
	sess.SetMetrics(met)
	sess.SetTuning(300*time.Millisecond, 200*time.Millisecond)
	installTunnelEvents(sess, snmpAgent, Options{
		Config: &config.Config{
			Role: config.RoleManager,
			Metrics: config.MetricsRole{
				Community:    "metcomm",
				TrapSinkAddr: sinkPC.LocalAddr().String(),
			},
		},
		Log: zap.NewNop(),
	})
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()
	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Kill the server listener + accepted sessions: client session drops
	// → tunnel-down event → trap at the sink.
	_ = lA.Close()
	wg.Wait()
	select {
	case dg := <-trapCh:
		validateTrap(t, dg)
	case <-time.After(10 * time.Second):
		t.Fatal("no tunnel-down trap within 10s")
	}
}

// validateTrap asserts a captured v2c trap: PDUSNMPv2Trap with
// snmpTrapOID.0 carrying a metrics events OID.
func validateTrap(t *testing.T, dg []byte) {
	t.Helper()
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		t.Fatalf("split trap: %v", err)
	}
	typ, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("parse trap: %v", err)
	}
	if typ != msg.PDUSNMPv2Trap {
		t.Fatalf("trap type 0x%02x, want SNMPv2Trap", typ)
	}
	found := false
	for rest := fields.Varbinds; len(rest) > 0; {
		tag, content, r, err := msg.NextTLV(rest)
		if err != nil || tag != 0x30 {
			break
		}
		rest = r
		oidTag, oidContent, _, err := msg.NextTLV(content)
		if err != nil || oidTag != 0x06 {
			continue
		}
		oid, err := msg.DecodeOID(oidContent)
		if err != nil {
			continue
		}
		if oid == "1.3.6.1.6.3.1.1.4.1.0" {
			found = true
		}
	}
	if !found {
		t.Fatal("trap carries no snmpTrapOID.0 varbind")
	}
}

// waitBoundSnmp polls until addr is bound (someone owns it).
func waitBoundSnmp(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.ListenPacket("udp", addr); err == nil {
			_ = conn.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatalf("address %s never became bound", addr)
}

// freeListenerDTLS binds a DTLS PSK listener on an ephemeral port
// (mirrors the tunnel package's freeListener; the tunnel helpers are not
// exported).
func freeListenerDTLS(t *testing.T) net.Listener {
	t.Helper()
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l
}

// TestRunAgentReadOnlyE2E pins the agent-side write policy: read_only on
// the DEVICE-facing box refuses a SET that arrives over the tunnel, so the
// device is protected even if the manager-side proxy (or the manager leg)
// is compromised. The clear v2c client must get notWritable (not a
// timeout) and the fake agent must never receive the write.
func TestRunAgentReadOnlyE2E(t *testing.T) {
	met := observ.NewMetrics()
	agent, sets := countingFakeAgent(t, "127.0.0.1:0")
	defer agent.Close()
	agentAddr := agent.LocalAddr().String()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = agentAddr
	agentCfg.Security.Mode = "usm-translate"
	agentCfg.Security.Users = testUsers()
	agentCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	agentCfg.Access = config.Access{ReadOnly: true}
	pol, err := agentCfg.AccessPolicy()
	if err != nil {
		t.Fatalf("agent access policy: %v", err)
	}
	agentListen := agentCfg.Tunnel.ListenAddr

	agCancel, agErr := startAgent(t, agentCfg, met, access.NewHolder(pol))
	defer agCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	mgrCfg.Security.Mode = "usm-translate"
	mgrCfg.Security.Users = testUsers()
	mgrCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	mgrListen := mgrCfg.Manager.ListenAddr

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrListen)

	g := gosnmpV2c(t, mgrListen)
	defer g.Conn.Close()

	// reads still work through the chain
	if _, gerr := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); gerr != nil {
		t.Fatalf("GET through read-only agent: %v", gerr)
	}

	res, serr := g.Set([]gosnmp.SnmpPDU{{
		Name:  "1.3.6.1.2.1.1.5.0",
		Type:  gosnmp.OctetString,
		Value: "nope",
	}})
	if serr != nil {
		t.Fatalf("SET returned a transport error instead of an error-status: %v", serr)
	}
	if res.Error != gosnmp.NotWritable {
		t.Fatalf("SET error-status = %v, want notWritable", res.Error)
	}
	if n := sets.Load(); n != 0 {
		t.Fatalf("refused SET reached the legacy agent %d time(s)", n)
	}

	stopRun(t, agCancel, agErr, "agent")
	stopRun(t, mgCancel, mgErr, "manager")
}

// counterValue reads a Prometheus counter without pulling in testutil.
func counterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// gaugeValue reads a Prometheus gauge (instrument.Write, not Collect).
func gaugeValue(t *testing.T, g interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// waitSessionsActive polls the cap-occupancy gauge until it equals want.
func waitSessionsActive(t *testing.T, met *observ.Metrics, want float64, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if gaugeValue(t, met.SessionsActive) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunAgentSessionCap pins the front-door resource bound: the agent
// tunnel listener serves at most tunnel.max_sessions concurrent sessions
// and closes any further conn immediately. Without the cap, an
// unauthenticated peer can pin one goroutine + one DTLS FSM per source
// port for the whole dead-peer window, which is exactly the pre-auth DoS
// the cap exists to prevent.
//
// The test also pins the recovery side: releasing a slot must let the next
// session in, otherwise a burst would wedge the proxy for its lifetime.
func TestRunAgentSessionCap(t *testing.T) {
	met := observ.NewMetrics()
	agent := fakeAgent(t, "127.0.0.1:0")
	defer agent.Close()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Tunnel.PSKIdentity = "cap-test"
	agentCfg.Tunnel.MaxSessions = 1
	agentCfg.Agent.AgentAddr = agent.LocalAddr().String()

	agCancel, agErr := startAgent(t, agentCfg, met)

	dialer := &tunnel.Dialer{
		Mode:        "dtls",
		RemoteAddr:  agentCfg.Tunnel.ListenAddr,
		PSK:         []byte("testpsk"),
		PSKIdentity: []byte("cap-test"),
		Timeout:     3 * time.Second,
	}
	// connect always returns the session so a failed attempt can be closed:
	// an abandoned client keeps retransmitting its ClientHello, and those
	// retransmissions are themselves new accepts that would compete for the
	// freed slot in the recovery check below.
	connect := func(timeout time.Duration) (*tunnel.Session, error) {
		sess := tunnel.NewClientSession(dialer, 65536, 1200, zap.NewNop())
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := sess.Connect(ctx)
		if err != nil {
			_ = sess.Close()
		}
		return sess, err
	}

	first, err := connect(10 * time.Second)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	if !waitSessionsActive(t, met, 1, 10*time.Second) {
		t.Fatalf("sessions_active never reached 1 with one accepted session (got %v)",
			gaugeValue(t, met.SessionsActive))
	}

	// Second concurrent session: the listener has one slot, which the
	// first session holds. The accept is refused immediately, so the
	// handshake never completes.
	start := time.Now()
	if second, serr := connect(2 * time.Second); serr == nil {
		_ = second.Close()
		t.Fatal("second concurrent session was served with max_sessions=1")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refused session took %s to fail; the cap should fail fast", elapsed)
	}
	if got := counterValue(t, met.SessionsDenied); got < 1 {
		t.Fatalf("sessions_denied_total = %v, want >= 1 (the refusal must be observable)", got)
	}

	// Release the slot and confirm the listener is not wedged: the session
	// teardown is asynchronous (the server notices the close on its next
	// read), so wait for the occupancy gauge to drop — the same signal an
	// operator watches — and only then require a successful handshake. A
	// fixed sleep here flakes under load, where teardown can lag by seconds.
	_ = first.Close()
	if !waitSessionsActive(t, met, 0, 15*time.Second) {
		t.Fatalf("the cap slot was never released after the session closed (sessions_active=%v)",
			gaugeValue(t, met.SessionsActive))
	}
	third, lastErr := connect(10 * time.Second)
	if third == nil {
		t.Fatalf("no session accepted after the slot was released: %v", lastErr)
	}
	_ = third.Close()

	stopRun(t, agCancel, agErr, "agent")
}
