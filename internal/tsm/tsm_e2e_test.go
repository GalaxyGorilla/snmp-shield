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
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/tsm"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
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
	pending  map[uint8][]*tunnel.Frame // frames sent before the peer subscribed
	peerCert *x509.Certificate
}

func newPipePair(agentCert *x509.Certificate) (mgr, agt *pipe) {
	mgr = &pipe{subs: make(map[uint8][]chan *tunnel.Frame), pending: make(map[uint8][]*tunnel.Frame)}
	agt = &pipe{subs: make(map[uint8][]chan *tunnel.Frame), pending: make(map[uint8][]*tunnel.Frame), peerCert: agentCert}
	mgr.other = agt
	agt.other = mgr
	return mgr, agt
}

func (p *pipe) Subscribe(ftype uint8) (<-chan *tunnel.Frame, func()) {
	ch := make(chan *tunnel.Frame, 64)
	p.mu.Lock()
	// deliver frames that arrived before this subscription (the real
	// tunnel buffers; the shim must too, or the trap path races startup)
	for _, f := range p.pending[ftype] {
		ch <- f
	}
	delete(p.pending, ftype)
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
// connection the peer sees. Frames sent before the peer subscribed are
// queued and delivered on Subscribe (mirrors real tunnel buffering;
// dropping them makes the trap path race translator startup).
func (p *pipe) Send(_ context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	o := p.other
	if o == nil {
		return nil
	}
	f := &tunnel.Frame{Type: typ, Flags: flags, CorrID: corrID, Payload: append([]byte(nil), payload...)}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.subs[typ]) == 0 {
		o.pending[typ] = append(o.pending[typ], f)
		return nil
	}
	for _, ch := range o.subs[typ] {
		ch <- f
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

// fakeAgentOnFreePort starts a fake v2c agent on an ephemeral local port
// and returns the conn plus its address. Fixed ports flake when the whole
// suite runs in parallel (test packages share the loopback namespace).
func fakeAgentOnFreePort(t *testing.T) (net.PacketConn, string) {
	t.Helper()
	conn, _, addr := countingFakeAgentOnFreePort(t)
	return conn, addr
}

// countingFakeAgentOnFreePort also counts the SET requests that reach the
// fake device (nil counter = not asked).
func countingFakeAgentOnFreePort(t *testing.T) (net.PacketConn, *atomic.Int32, string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sets := new(atomic.Int32)
	go agentLoop(conn, sets)
	return conn, sets, conn.LocalAddr().String()
}

func agentLoop(conn net.PacketConn, sets *atomic.Int32) {
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
		if sets != nil {
			if info, ierr := msg.Peek(dg); ierr == nil && msg.IsSet(info.PDUType) {
				sets.Add(1)
			}
		}
		resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
		out, err := msg.BuildV1V2c(ver, community, resp)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(out, from)
	}
}

// --- translator pair over the pipe ------------------------------------------------

type tsmPair struct {
	stop func()
	sets *atomic.Int32 // SET requests that reached the fake device
}

// newTSMPair builds a manager+agent translator pair over the pipe. An
// optional access holder is installed on the AGENT side (the device-facing
// box), which is where read_only/write_policy protect the device.
func newTSMPair(t *testing.T, agentCertCN string, identities []string, holders ...*access.Holder) (*tsmPair, string) {
	t.Helper()

	var h *access.Holder
	if len(holders) > 0 {
		h = holders[0]
	}

	fake, sets, fakeAddr := countingFakeAgentOnFreePort(t)

	var agentCert *x509.Certificate
	if agentCertCN != "" {
		agentCert = testCert(t, agentCertCN)
	}
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: identities}
	agentRole := config.AgentRole{
		AgentAddr:      fakeAddr,
		AgentCommunity: "realcomm",
	}
	atr, err := tsm.NewAgentTranslator(agentRole, agentSec, agtPipe, zap.NewNop(), nil)
	if err != nil {
		fake.Close()
		t.Fatal(err)
	}
	atr.SetAccess(h)

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
	startTSMManager(t, mtr, done)

	return &tsmPair{stop: func() { close(done); fake.Close() }, sets: sets}, mgrAddr
}

// startTSMManager starts a manager and waits for its explicit readiness
// signal. Probing readiness by binding its UDP address races with its own
// listener startup on Darwin.
func startTSMManager(t *testing.T, mtr *tsm.ManagerTranslator, done <-chan struct{}) {
	t.Helper()
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- mtr.Run(done, ready)
		close(runErr)
	}()
	select {
	case <-ready:
		return
	case err, ok := <-runErr:
		if !ok {
			t.Fatal("TSM manager exited during startup without an error")
		}
		t.Fatalf("TSM manager exited during startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for TSM manager startup")
	}
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
	pair, mgrAddr := newTSMPair(t, "snmp-shield-manager", []string{"snmp-shield-manager"})
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
	pair, mgrAddr := newTSMPair(t, "snmp-shield-manager", []string{"some-other-identity"})
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

	fake, fakeAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	agentCert := testCert(t, "snmp-shield-manager")
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: []string{"snmp-shield-manager"}}
	agentRole := config.AgentRole{
		AgentAddr:         fakeAddr,
		TrapSinkAddr:      sinkAddr,
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
	startTSMManager(t, mtr, done)

	trapRaddr, _ := net.ResolveUDPAddr("udp", trapAddr)

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

// TestTSMEndToEndInform: clear v2c inform from a device at the manager's
// trap listener -> manager tracks a pending inform (tunnel corrID) and ships
// a NOTIF frame with FlagInform -> agent translator answers with a RESP
// FlagInform frame (corrID preserved) -> the manager's inform response path
// rebuilds the clear GetResponse and delivers it back to the device at the
// trap listener (req-id echoed). Pins the inform relay fix: before, the
// response was dropped by handleTunnelResponse ("no pending request").
func TestTSMEndToEndInform(t *testing.T) {
	fake, fakeAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	agentCert := testCert(t, "snmp-shield-manager")
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: []string{"snmp-shield-manager"}}
	agentRole := config.AgentRole{
		AgentAddr:      fakeAddr,
		AgentCommunity: "realcomm",
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
	startTSMManager(t, mtr, done)

	// device socket: the inform's sender address (its reply address)
	device, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	trapRaddr, _ := net.ResolveUDPAddr("udp", trapAddr)

	// clear v2c inform (req-id 777, sysUpTime + snmpTrapOID.0 varbinds)
	informPDU := msg.BuildPDU(msg.PDUInformRequest, 777, 0, 0, buildInformVarbinds(t))
	inform, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), informPDU)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := device.WriteTo(inform, trapRaddr); err != nil {
		t.Fatal(err)
	}

	// the manager must rebuild and deliver the clear inform response
	device.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := device.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no inform response from manager: %v", err)
	}
	ver, community, pduTLV, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad inform response: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("inform response version = %d, want 2c", ver)
	}
	if string(community) != "devicecomm" {
		t.Fatalf("inform response community = %q, want devicecomm", community)
	}
	_, fields, err := msg.ParsePDU(pduTLV)
	if err != nil {
		t.Fatalf("bad inform response PDU: %v", err)
	}
	if fields.ReqID != 777 {
		t.Fatalf("inform response reqID = %d, want 777", fields.ReqID)
	}
}

// buildInformVarbinds returns a varbind SEQUENCE content for an inform:
// sysUpTime.0 (TimeTicks) + snmpTrapOID.0 (coldStart OID).
func buildInformVarbinds(t *testing.T) []byte {
	t.Helper()
	uptime, err := msg.EncodeOID("1.3.6.1.2.1.1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	trapOID, err := msg.EncodeOID("1.3.6.1.6.3.1.1.5.1")
	if err != nil {
		t.Fatal(err)
	}
	vb1 := msg.AppendTLV(nil, 0x30, msg.AppendTLV(nil, 0x06, uptime))
	vb1 = msg.AppendTLV(vb1, 0x43, []byte{0, 0, 0, 100}) // TimeTicks value
	vb2 := msg.AppendTLV(nil, 0x30, msg.AppendTLV(nil, 0x06, trapOID))
	vb2 = msg.AppendTLV(vb2, 0x06, trapOID)
	// BuildPDU wraps the varbind-list SEQUENCE itself: pass the RAW
	// varbind-list content (the two varbind TLVs concatenated).
	list := append(append([]byte{}, vb1...), vb2...)
	return msg.AppendTLV(nil, 0x30, list)
}

// TestTSMEndToEndAgentInform: the agent side originates an inform (v3 TSM
// NOTIF frame with PDUInformRequest) for its local devices; the manager
// translator's handleTunnelNotif answers with a RESP FlagInform frame
// (corrID preserved, req-id + securityName + sec-level flags echoed per the
// TSM response echo rule). Pins the manager-side inbound-inform answering.
func TestTSMEndToEndAgentInform(t *testing.T) {
	agentCert := testCert(t, "snmp-shield-manager")
	mgrPipe, agtPipe := newPipePair(agentCert)

	agentSec := config.Security{Mode: "tsm", TSMIdentities: []string{"snmp-shield-manager"}}
	agentRole := config.AgentRole{AgentAddr: "127.0.0.1:9", AgentCommunity: "realcomm"}
	atr, err := tsm.NewAgentTranslator(agentRole, agentSec, agtPipe, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	mgrRole := config.ManagerRole{ListenAddr: "127.0.0.1:0"}
	mgrSec := config.Security{Mode: "tsm", TrapCommunity: "trapcomm"}
	mtr, err := tsm.NewManagerTranslator(mgrRole, mgrSec, mgrPipe, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() { _ = atr.Run(done) }()
	go func() { _ = mtr.Run(done) }()

	// subscribe on the agent side before triggering (blocking pipe keeps
	// the frame until a subscriber drains it, but be explicit)
	respCh, cancel := agtPipe.Subscribe(2) // 2 = RESP (frame type)
	defer cancel()

	// agent-originated inform: v3 TSM NOTIF (PDUInformRequest req-id 888,
	// securityName from the peer cert CN)
	informPDU := msg.BuildPDU(msg.PDUInformRequest, 888, 0, 0, buildInformVarbinds(t))
	scoped := msg.BuildScoped(nil, []byte{}, informPDU)
	notif, err := msg.BuildV3(msg.V3Header{
		MsgID:      7,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{UserName: "snmp-shield-manager"}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agtPipe.Send(context.Background(), 3, 0, 42, notif); err != nil { // 3 = NOTIF, agent -> manager
		t.Fatal(err)
	}

	// the manager's answer must arrive as a RESP FlagInform frame
	select {
	case f := <-respCh:
		if f.Type != 2 { // RESP
			t.Fatalf("frame type = %d, want RESP", f.Type)
		}
		if f.Flags&0x01 == 0 {
			t.Fatalf("frame flags = %#x, want FlagInform set", f.Flags)
		}
		if f.CorrID != 42 {
			t.Fatalf("frame corrID = %d, want 42", f.CorrID)
		}
		m2, err := msg.ParseV3(f.Payload)
		if err != nil {
			t.Fatalf("bad v3 inform response: %v", err)
		}
		if m2.Header.SecModel != msg.SecurityModelTSM {
			t.Fatalf("secModel = %d, want TSM", m2.Header.SecModel)
		}
		if m2.USM.UserName != "" {
			t.Fatalf("securityName = %q, want empty (TSM secParams are empty per RFC 5591)", m2.USM.UserName)
		}
		if m2.Header.MsgFlags&msg.MsgFlagReportable == 0 {
			t.Fatalf("flags = %#x, want Reportable echoed", m2.Header.MsgFlags)
		}
		// plaintext TSM: m2.PDU is the raw inner PDU TLV (no decryption)
		pdu := m2.PDU
		_, pfields, err := msg.ParsePDU(pdu)
		if err != nil {
			t.Fatalf("bad response PDU: %v", err)
		}
		if pfields.ReqID != 888 {
			t.Fatalf("response reqID = %d, want 888", pfields.ReqID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no inform response from manager translator")
	}
}

// TestTSMEndToEndAgentReadOnly pins the agent-side write policy of the TSM
// two-proxy chain: read_only on the device-facing box refuses a SET with
// notWritable (relayed back to the clear v2c client) and the device never
// sees it.
func TestTSMEndToEndAgentReadOnly(t *testing.T) {
	pol, err := access.New(nil, 0, access.NewReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	pair, mgrAddr := newTSMPair(t, "snmp-shield-manager", []string{"snmp-shield-manager"}, access.NewHolder(pol))
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

	// v2c SET for sysName.0
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	vb := msg.AppendTLV(nil, 0x06, oid)
	vb = msg.AppendTLV(vb, 0x04, []byte("nope"))
	vbs := msg.AppendTLV(nil, 0x30, vb)
	reqID := int32(7777)
	pdu := msg.BuildPDU(msg.PDUSetRequest, reqID, 0, 0, vbs)
	req, err := msg.BuildV1V2c(msg.Version2c, []byte("clientcomm"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo(req, raddr); err != nil {
		t.Fatal(err)
	}

	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no answer for the refused SET (timeout instead of notWritable): %v", err)
	}
	_, _, pduTLV, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("bad response: %v", err)
	}
	_, fields, err := msg.ParsePDU(pduTLV)
	if err != nil {
		t.Fatalf("bad response PDU: %v", err)
	}
	if fields.ErrStatus != msg.ErrStatusNotWritable {
		t.Errorf("errStatus = %d, want notWritable (%d)", fields.ErrStatus, msg.ErrStatusNotWritable)
	}
	if fields.ReqID != reqID {
		t.Errorf("response req-id = %d, want %d", fields.ReqID, reqID)
	}
	if n := pair.sets.Load(); n != 0 {
		t.Errorf("refused SET reached the legacy device %d time(s)", n)
	}
}
