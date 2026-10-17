// tsm_e2e_test.go (package tsm_test): end-to-end TSM translator tests over
// an in-memory FrameSink pipe. A v2c client speaks to the manager-side
// translator's clear listener; the manager translator wraps PDUs in v3 TSM
// messages (secModel=4, empty security parameters), the agent translator
// unwraps them (validating the shim's peer certificate), forwards to a fake
// v2c agent, and the response path returns the answer to the client.
package tsm_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kattelma/snmp-proxy/internal/config"
	"github.com/kattelma/snmp-proxy/internal/msg"
	"github.com/kattelma/snmp-proxy/internal/tsm"
	"github.com/kattelma/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// --- in-memory tunnel pipe ---------------------------------------------------

// pipe is one end of a bidirectional in-memory tunnel. Sends are routed to
// the OTHER end's subscribers (manager <-> agent). peerCert emulates the
// tunnel peer certificate (nil = no certificates, peer-reject case).
type pipe struct {
	other    *pipe
	mu       sync.Mutex
	subs     map[uint8][]chan *tunnel.Frame
	peerCert *x509.Certificate
}

func newPipePair(agentCert *x509.Certificate) (mgr, agt *pipe) {
	mgr = &pipe{subs: make(map[uint8][]chan *tunnel.Frame)}
	agt = &pipe{subs: make(map[uint8][]chan *tunnel.Frame), peerCert: agentCert}
	mgr.other = agt
	agt.other = mgr
	return mgr, agt
}

func (p *pipe) Subscribe(ftype uint8) (<-chan *tunnel.Frame, func()) {
	ch := make(chan *tunnel.Frame, 64)
	p.mu.Lock()
	p.subs[ftype] = append(p.subs[ftype], ch)
	p.mu.Unlock()
	cancel := func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, c := range p.subs[ftype] {
			if c == ch {
				p.subs[ftype] = append(p.subs[ftype][:i], p.subs[ftype][i+1:]...)
				break
			}
		}
	}
	return ch, cancel
}

// Send delivers to the OTHER end's subscribers: this end acts as the tunnel
// connection the peer sees.
func (p *pipe) Send(_ context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	o := p.other
	if o == nil {
		return nil
	}
	o.mu.Lock()
	subs := append([]chan *tunnel.Frame(nil), o.subs[typ]...)
	o.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- &tunnel.Frame{Type: typ, Flags: flags, CorrID: corrID, Payload: append([]byte(nil), payload...)}:
		default:
		}
	}
	return nil
}

// PeerCerts satisfies the agent translator's peerCertsSource (the peer
// certificate chain of the tunnel connection as seen by this end).
func (p *pipe) PeerCerts() []*x509.Certificate {
	if p.peerCert == nil {
		return nil
	}
	return []*x509.Certificate{p.peerCert}
}

// --- test certificate ---------------------------------------------------------

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// --- fake v2c agent -------------------------------------------------------------

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

// --- translator pair over the pipe ------------------------------------------------

type tsmPair struct {
	mgrConn net.PacketConn // clear leg facing the v2c client
	stop    func()
}

func newTSMPair(t *testing.T, agentCertCN string, identities []string) (*tsmPair, string) {
	t.Helper()

	fake := fakeAgent(t, "127.0.0.1:11811")

	var agentCert *x509.Certificate
	if agentCertCN != "" {
		agentCert = testCert(t, agentCertCN)
	}
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: identities}
	agentRole := config.AgentRole{
		AgentAddr:      "127.0.0.1:11811",
		AgentCommunity: "realcomm",
	}
	atr, err := tsm.NewAgentTranslator(agentRole, agentSec, agtPipe, zap.NewNop(), nil)
	if err != nil {
		fake.Close()
		t.Fatal(err)
	}

	mgrAddr := freeUDPPort(t)
	mgrSec := config.Security{Mode: "tsm", TrapCommunity: "trapcomm"}
	mgrRole := config.ManagerRole{ListenAddr: mgrAddr}
	mtr, err := tsm.NewManagerTranslator(mgrRole, mgrSec, mgrPipe, zap.NewNop(), nil)
	if err != nil {
		fake.Close()
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { _ = atr.Run(done) }()
	go func() { _ = mtr.Run(done) }()

	// wait until the manager clear socket is bound (Run binds before its
	// read loop starts; probe with a UDP connect until it answers or the
	// port stops being bindable — simplest reliable check: try binding it
	// ourselves until it fails, meaning the translator owns it)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.ListenUDP("udp", raddr0(mgrAddr)); err != nil {
			break // translator owns the port now
		} else {
			c.Close()
			time.Sleep(20 * time.Millisecond)
		}
	}

	return &tsmPair{stop: func() { close(done); fake.Close() }}, mgrAddr
}

// raddr0 resolves a UDP address (test helper).
func raddr0(addr string) *net.UDPAddr {
	u, _ := net.ResolveUDPAddr("udp", addr)
	return u
}

// freeUDPPort returns a free loopback UDP port (binds and closes), with a
// short re-bind check to reduce the probe-close race window.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 10; i++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		addr := conn.LocalAddr().String()
		conn.Close()
		// re-bind check: if another process took it, try again
		if c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.UDPAddr).Port}); err == nil {
			c2.Close()
			return addr
		}
	}
	t.Fatal("could not find a stable free UDP port")
	return ""
}

// --- tests -------------------------------------------------------------------------

// TestTSMEndToEndGet: v2c GET -> manager TSM translator -> pipe -> agent TSM
// translator (peer cert CN allowed) -> fake v2c agent -> response back.
func TestTSMEndToEndGet(t *testing.T) {
	pair, mgrAddr := newTSMPair(t, "snmp-proxy-manager", []string{"snmp-proxy-manager"})
	defer pair.stop()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	raddr, err := net.ResolveUDPAddr("udp", mgrAddr)
	if err != nil {
		t.Fatal(err)
	}

	// v2c GET request for sysDescr with a marker value
	reqID := int32(4242)
	varbinds := buildGetVarbinds(t)
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0, varbinds)
	req, err := msg.BuildV1V2c(msg.Version2c, []byte("clientcomm"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo(req, raddr); err != nil {
		t.Fatal(err)
	}

	// response: same reqID echoed by the fake agent
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response from translator pair: %v", err)
	}
	ver, community, pduTLV, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("response version = %d, want %d", ver, msg.Version2c)
	}
	if string(community) != "clientcomm" {
		t.Fatalf("response community = %q, want clientcomm", community)
	}
	_, fields, err := msg.ParsePDU(pduTLV)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if fields.ReqID != reqID {
		t.Fatalf("response reqID = %d, want %d", fields.ReqID, reqID)
	}
}

// buildGetVarbinds returns a varbind SEQUENCE content for a GET of sysDescr.
func buildGetVarbinds(t *testing.T) []byte {
	t.Helper()
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	vb := msg.AppendTLV(nil, 0x30, msg.AppendTLV(nil, 0x06, oid))
	return msg.AppendTLV(nil, 0x30, vb)
}

// TestTSMEndToEndWrongPeer: with an identity allow-list that does not
// contain the shim's peer CN, requests must be dropped (no response).
func TestTSMEndToEndWrongPeer(t *testing.T) {
	pair, mgrAddr := newTSMPair(t, "snmp-proxy-manager", []string{"some-other-identity"})
	defer pair.stop()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	raddr, err := net.ResolveUDPAddr("udp", mgrAddr)
	if err != nil {
		t.Fatal(err)
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 4242, 0, 0, buildGetVarbinds(t))
	req, err := msg.BuildV1V2c(msg.Version2c, []byte("clientcomm"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo(req, raddr); err != nil {
		t.Fatal(err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	if n, _, err := client.ReadFrom(buf); err == nil {
		t.Fatalf("expected drop for unknown peer, got response of %d bytes", n)
	}
}

// TestTSMEndToEndTrapPath: v1 trap -> agent-side trap listener? The manager
// translator owns the trap listener (local devices); here: manager-side
// clear trap -> NOTIF frame -> agent translator -> fake sink. Also informs
// are answered. We exercise the reverse direction: manager clear trap ships
// over the tunnel and reaches the agent-side trap sink.
func TestTSMEndToEndTrapPath(t *testing.T) {
	// fake trap sink on the agent side
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sinkAddr := sink.LocalAddr().String()
	sinkGot := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65536)
		n, _, err := sink.ReadFrom(buf)
		if err == nil {
			sinkGot <- append([]byte(nil), buf[:n]...)
		}
	}()

	fake := fakeAgent(t, "127.0.0.1:11811")
	defer fake.Close()

	agentCert := testCert(t, "snmp-proxy-manager")
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: []string{"snmp-proxy-manager"}}
	agentRole := config.AgentRole{
		AgentAddr:      "127.0.0.1:11811",
		TrapSinkAddr:   sinkAddr,
		TrapSinkCommunity: "sinkcomm",
	}
	atr, err := tsm.NewAgentTranslator(agentRole, agentSec, agtPipe, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	mgrAddr := freeUDPPort(t)
	trapAddr := freeUDPPort(t)
	mgrSec := config.Security{Mode: "tsm", TrapCommunity: "trapcomm"}
	mgrRole := config.ManagerRole{ListenAddr: mgrAddr, TrapListenAddr: trapAddr}
	mtr, err := tsm.NewManagerTranslator(mgrRole, mgrSec, mgrPipe, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() { _ = atr.Run(done) }()
	go func() { _ = mtr.Run(done) }()

	// wait for the trap socket to be bound (same probe as newTSMPair)
	trapRaddr, _ := net.ResolveUDPAddr("udp", trapAddr)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.ListenUDP("udp", trapRaddr); err != nil {
			break
		} else {
			c.Close()
			time.Sleep(20 * time.Millisecond)
		}
	}

	// send a v1 coldStart trap from a local device (full v1 message:
	// version + community + Trap-PDU)
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
	if _, err := net.DialUDP("udp", nil, trapRaddr); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(trap, trapRaddr); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-sinkGot:
		ver, community, pduTLV, err := msg.SplitV1V2c(got)
		if err != nil {
			t.Fatalf("bad sink datagram: %v", err)
		}
		if ver != msg.Version2c {
			t.Fatalf("sink version = %d, want 2c", ver)
		}
		if string(community) != "sinkcomm" {
			t.Fatalf("sink community = %q, want sinkcomm", community)
		}
		_, fields, err := msg.ParsePDU(pduTLV)
		if err != nil {
			t.Fatalf("bad sink PDU: %v", err)
		}
		if len(fields.Varbinds) == 0 {
			t.Fatal("sink varbinds empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trap never reached the agent-side sink")
	}
}

// mustOID encodes a dotted OID (test helper).
func mustOID(t *testing.T, dotted string) []byte {
	t.Helper()
	oid, err := msg.EncodeOID(dotted)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}
