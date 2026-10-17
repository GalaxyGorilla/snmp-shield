// translate_manager_e2e_test.go (package usm): end-to-end regression tests
// for the FULL two-proxy USM translate chain — the real manager-side
// translator wired to the real agent-side translator through a pipe shim
// (frames routed both ways, mirroring tunnel semantics: you never receive
// your own frames), with a fake clear v2c agent on loopback UDP. Uses
// gosnmp as an independent client oracle where possible and raw msg
// builders for datagrams.
package usm

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// pipeEnd is one side of an in-memory two-way FrameSink pipe. Send routes
// the frame to the PEER's subscribers of the given type (frames are
// delivered as fresh *tunnel.Frame copies with the CorrID preserved).
type pipeEnd struct {
	mu   sync.Mutex
	subs map[uint8][]chan *tunnel.Frame
	peer *pipeEnd
}

func newPipe() (*pipeEnd, *pipeEnd) {
	a := &pipeEnd{subs: make(map[uint8][]chan *tunnel.Frame)}
	b := &pipeEnd{subs: make(map[uint8][]chan *tunnel.Frame)}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *pipeEnd) Subscribe(ftype uint8) (<-chan *tunnel.Frame, func()) {
	ch := make(chan *tunnel.Frame, 64)
	p.mu.Lock()
	p.subs[ftype] = append(p.subs[ftype], ch)
	p.mu.Unlock()
	return ch, func() {}
}

func (p *pipeEnd) Send(_ context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	f := &tunnel.Frame{Type: typ, Flags: flags, CorrID: corrID, Payload: append([]byte{}, payload...)}
	p.peer.mu.Lock()
	defer p.peer.mu.Unlock()
	// blocking send: peers are Run-loop subscribers that always drain, so
	// blocking mirrors real tunnel delivery (no silent frame loss).
	for _, ch := range p.peer.subs[typ] {
		ch <- f
	}
	return nil
}

// --- fake clear v2c agent ----------------------------------------------------

// fakeV2cAgent answers GET/GETNEXT with a simple OID=value binding, like the
// interop scripts' Python agent. Records the last request per community.
type fakeV2cAgent struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	lastComm string
}

func startFakeV2cAgent(t *testing.T) *fakeV2cAgent {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fa := &fakeV2cAgent{conn: conn}
	go fa.loop()
	return fa
}

func (fa *fakeV2cAgent) loop() {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := fa.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dg := append([]byte{}, buf[:n]...)
		ver, comm, pdu, err := msg.SplitV1V2c(dg)
		if err != nil {
			continue
		}
		fa.mu.Lock()
		fa.lastComm = string(comm)
		fa.mu.Unlock()
		fields, ok := pduCommon(pdu)
		if !ok || len(fields.Varbinds) == 0 {
			continue
		}
		// respond: same type, echo req-id, one binding oid=OCTET "pong"
		oidDotted := pduOID(fields.Varbinds)
		oidBytes, oerr := msg.EncodeOID(oidDotted)
		if oerr != nil {
			continue
		}
		resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, singleBinding(oidBytes))
		out, err := msg.BuildV1V2c(ver, comm, resp)
		if err != nil {
			continue
		}
		fa.conn.WriteToUDP(out, raddr)
	}
}

// tlvBody returns the content and the remainder after the TLV starting at
// tlv (tag octet + length + content).
func tlvBody(tlv []byte) ([]byte, []byte, error) {
	if len(tlv) < 2 {
		return nil, nil, errTrunc
	}
	l, rest, err := berLenAt(tlv[1:])
	if err != nil || len(rest) < l {
		return nil, nil, errTrunc
	}
	return rest[:l], rest[l:], nil
}

// pduOID extracts the first varbind OID dotted string from raw varbind-list
// content (varbind SEQUENCE content = OID TLV + value TLV).
func pduOID(varbinds []byte) string {
	if len(varbinds) < 4 || varbinds[0] != 0x30 {
		return ""
	}
	body, _, err := tlvBody(varbinds)
	if err != nil || len(body) < 2 || body[0] != 0x06 {
		return ""
	}
	oidBytes, err := berContentOf(body[1:])
	if err != nil {
		return ""
	}
	dotted, err := msg.DecodeOID(oidBytes)
	if err != nil {
		return ""
	}
	return dotted
}

// singleBinding builds raw varbind-list content: one binding
// (oid, OCTET STRING "pong").
func singleBinding(oidBytes []byte) []byte {
	vb := append(AppendTLVNil(0x06, oidBytes), AppendTLVNil(0x04, []byte("pong"))...)
	return append([]byte{}, AppendTLVNil(0x30, vb)...)
}

// --- chain harness ------------------------------------------------------------

// chainHarness wires the real manager-side translator to the real agent-side
// translator through a pipe shim, with a fake clear v2c agent on loopback.
type chainHarness struct {
	sender *net.UDPConn // separate sender socket to the manager's clear listener (mgr.conn belongs to Run's goroutine)
	agent  *fakeV2cAgent
	mgr    *ManagerTranslator
	agt    *AgentTranslator
	pipe   *pipeEnd
}

// startChain builds and starts both translators with the given users and an
// optional notify filter (applied on the manager-side trap ingress).
func startChain(t *testing.T, filt *notifyfilter.Filter) *chainHarness {
	t.Helper()

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	users := []Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
	}}

	// manager-side clear listener: bind an ephemeral port, hand the PORT to
	// the translator config so Run() re-binds the same address (Run owns
	// its socket; the harness uses a separate sender socket on any port).
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probe.LocalAddr().String()
	probe.Close()

	agent := startFakeV2cAgent(t)

	// both translators share the same engine clock: the agent side is the
	// authoritative engine, the manager side discovers it via reports.
	mcfg := config.ManagerRole{ListenAddr: listenPort}
	sec := config.Security{
		Users: []config.UserCfg{{
			Name:           "proxy",
			AuthProtocol:   "sha",
			AuthPassphrase: "authpass",
			PrivProtocol:   "aes",
			PrivPassphrase: "privpass",
		}},
	}
	pa, pb := newPipe()
	h := &chainHarness{agent: agent, pipe: pa}
	mgr, err := NewManagerTranslator(mcfg, sec, clock, pa, zap.NewNop(), nil, filt)
	if err != nil {
		t.Fatal(err)
	}
	h.mgr = mgr
	agt, err := NewAgentTranslator(config.AgentRole{AgentAddr: agent.conn.LocalAddr().String()}, users, clock, pb, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h.agt = agt

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() { _ = mgr.Run(done) }()
	go func() { _ = agt.Run(done) }()

	// grace period: both Run loops subscribe to the pipe and bind their
	// sockets during startup. Reading mgr.conn/agt.agentConn here would
	// race the Run goroutines, so wait on an OS-observable instead: the
	// clear listener port must answer a datagram round-trip. The retry
	// loops in the tests (clearGet) absorb the rest of the startup race.
	// Blocking pipe sends make frame loss impossible once subscribed.
	time.Sleep(100 * time.Millisecond)
	sender, err := net.DialUDP("udp", nil, probeAddr(t, listenPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sender.Close() })
	h.sender = sender
	return h
}

// probeAddr resolves an address string for DialUDP.
func probeAddr(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// clearGet sends a clear v2c GET from a manager and returns the response
// datagram (timeout = no response).
func (h *chainHarness) clearGet(t *testing.T, community, oidDotted string) ([]byte, bool) {
	t.Helper()
	oidBytes, err := msg.EncodeOID(oidDotted)
	if err != nil {
		t.Fatal(err)
	}
	reqID := int32(4242)
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0, singleBinding(oidBytes))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte(community), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.sender.Write(dg); err != nil {
		t.Fatal(err)
	}
	h.sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := h.sender.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// startChainSink builds the chain with the agent-side translator's trap
// sink pre-configured (read-safe: set before Run starts).
func startChainSink(t *testing.T, filt *notifyfilter.Filter, trapSink string) *chainHarness {
	t.Helper()
	h := startChain(t, filt)
	h.agt.cfg.TrapSinkAddr = trapSink
	return h
}

// TestChainDiscoveryAndGET pins the full request path: clear v2c GET from a
// manager -> discovery (Reportable empty GET) -> v3 authPriv across the
// shim -> agent side verify/decrypt -> clear v2c GET to the fake agent ->
// response back through v3 authPriv -> clear v2c response for the manager.
// The manager's req-id must be echoed and the fake agent must see the
// agent-side community.
func TestChainDiscoveryAndGET(t *testing.T) {
	h := startChain(t, nil)

	// first request performs engine discovery; retry once in case the
	// very first GET races the initial discovery round.
	var resp []byte
	var ok bool
	for i := 0; i < 3 && !ok; i++ {
		resp, ok = h.clearGet(t, "public", "1.3.6.1.2.1.1.1.0")
		if !ok {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("no clear response from the two-proxy chain")
	}
	ver, comm, pdu, err := msg.SplitV1V2c(resp)
	if err != nil {
		t.Fatalf("undecodable clear response: %v", err)
	}
	if ver != msg.Version2c || string(comm) != "public" {
		t.Fatalf("bad response version/community: %d %q", ver, comm)
	}
	fields, ok2 := pduCommon(pdu)
	if !ok2 {
		t.Fatal("undecodable response PDU")
	}
	if fields.ReqID != 4242 {
		t.Fatalf("client req-id not echoed: %d", fields.ReqID)
	}
	if len(fields.Varbinds) == 0 {
		t.Fatal("no varbinds in response")
	}
	// the fake agent answers oid=OCTET "pong"
	gotOID := pduOID(fields.Varbinds)
	if gotOID != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("unexpected response OID %q", gotOID)
	}

	// the fake agent must have seen the agent-side community ("public":
	// user 'proxy' has no per-user community override)
	h.agent.mu.Lock()
	comm2 := h.agent.lastComm
	h.agent.mu.Unlock()
	if comm2 != "public" {
		t.Fatalf("fake agent saw community %q, want public", comm2)
	}
}

// TestChainTrapRelayToSink pins the trap direction: a clear v2c trap from a
// device is wrapped into v3 authPriv NOTIF by the manager side, delivered
// through the shim, verified/unwrapped by the agent side and delivered to
// its clear v2c trap sink with the agent-side trap community.
func TestChainTrapRelayToSink(t *testing.T) {
	// clear v2c trap sink on the agent side
	sinkAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp", sinkAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// start the chain with the trap sink pre-wired (set before Run)
	h := startChainSink(t, nil, sink.LocalAddr().String())

	// establish engine state with a GET (discovery) first
	for i := 0; i < 3; i++ {
		if _, ok := h.clearGet(t, "public", "1.3.6.1.2.1.1.1.0"); ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// build a clear v2c trap: sysUpTime.0 + snmpTrapOID.0 coldStart
	oidBytes, err := msg.EncodeOID("1.3.6.1.6.3.1.1.5.1")
	if err != nil {
		t.Fatal(err)
	}
	var vbs []byte
	vbs = appendBinding(vbs, msg.OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
	vbs = appendBinding(vbs, msg.OIDSnmpTrapOID, 0x06, oidBytes)
	trapPDU := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vbs)
	trapDG, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), trapPDU)
	if err != nil {
		t.Fatal(err)
	}

	// feed the trap through the manager-side ingress (the same code path
	// readTraps drives); the agent-side sink was pre-wired at startup.
	h.mgr.handleClearTrap(append([]byte{}, trapDG...))

	sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no trap at the agent-side sink: %v", err)
	}
	sinkDG := buf[:n]
	ver, comm, pdu, err := msg.SplitV1V2c(sinkDG)
	if err != nil {
		t.Fatalf("undecodable sink trap: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("sink trap version: %d", ver)
	}
	if string(comm) != "public" {
		t.Fatalf("sink trap community %q, want public", comm)
	}
	f, ok := pduCommon(pdu)
	if !ok || f.ReqID != 0 {
		t.Fatalf("bad sink trap PDU: ok=%v reqID=%d", ok, f.ReqID)
	}
	oids := trapVarbindOIDs(f.Varbinds)
	if len(oids) < 2 || oids[0] != "1.3.6.1.2.1.1.3.0" || oids[1] != "1.3.6.1.6.3.1.1.4.1.0" {
		t.Fatalf("unexpected sink trap varbind OIDs: %v", oids)
	}
	vals := trapVarbindValues(f.Varbinds)
	if len(vals) >= 2 {
		// trapVarbindValues already returns the value-TLV content (the raw
		// OID sub-identifier bytes for snmpTrapOID)
		if dotted, derr := msg.DecodeOID(vals[1]); derr != nil || dotted != "1.3.6.1.6.3.1.1.5.1" {
			t.Fatalf("snmpTrapOID value % x (%q, err %v), want 1.3.6.1.6.3.1.1.5.1", vals[1], dotted, derr)
		}
	}
}

// trapVarbindOIDs returns the dotted OID of every varbind in raw varbind-list
// content.
func trapVarbindOIDs(varbinds []byte) []string {
	var oids []string
	for rest := varbinds; len(rest) >= 2 && rest[0] == 0x30; {
		body, tail, err := tlvBody(rest)
		if err != nil {
			break
		}
		if len(body) >= 2 && body[0] == 0x06 {
			oidBytes, err := berContentOf(body[1:])
			if err == nil {
				if dotted, derr := msg.DecodeOID(oidBytes); derr == nil {
					oids = append(oids, dotted)
				}
			}
		}
		rest = tail
	}
	return oids
}

// trapVarbindValues returns the raw value TLV bytes of every varbind in raw
// varbind-list content.
func trapVarbindValues(varbinds []byte) [][]byte {
	var vals [][]byte
	for rest := varbinds; len(rest) >= 2 && rest[0] == 0x30; {
		body, tail, err := tlvBody(rest)
		if err != nil {
			break
		}
		if len(body) >= 2 {
			_, afterOID, err := tlvBody(body)
			if err == nil && len(afterOID) >= 2 {
				content, cerr := berContentOf(afterOID[1:])
				if cerr == nil {
					vals = append(vals, content)
				}
			}
		}
		rest = tail
	}
	return vals
}

// buildAgentNotif wraps a clear PDU into a v3 authPriv NOTIF message the
// way the agent-side trap engine does: own engine state, salt counter,
// signing with the primary user's keys.
func buildAgentNotif(t *testing.T, agt *AgentTranslator, scoped []byte) ([]byte, error) {
	t.Helper()
	users := profilesFromConfig(config.Security{
		Users: []config.UserCfg{{
			Name:           "proxy",
			AuthProtocol:   "sha",
			AuthPassphrase: "authpass",
			PrivProtocol:   "aes",
			PrivPassphrase: "privpass",
		}},
	})
	if len(users) == 0 {
		t.Fatal("no users")
	}
	c, ok := agt.prof.Lookup(users[0].Name)
	if !ok {
		t.Fatal("user not found in agent profiles")
	}
	engineID := agt.clock.EngineID()
	boots := agt.clock.Boots()
	etime := agt.clock.Time()
	privParams := agt.salt.NextAES()
	authParams := make([]byte, c.p.AuthProtocol.MacLength())
	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, privParams, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(agt.msgID.Add(1)),
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   engineID,
		Boots:      boots,
		Time:       etime,
		UserName:   users[0].Name,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, encrypt)
	if err != nil {
		return nil, err
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		return nil, err
	}
	return out, nil
}

// TestChainAgentNotifToManagerSink pins the reverse notification direction:
// the agent side originates a v3 authPriv NOTIF for its local devices, the
// manager side verifies/unwraps it (per-engine keys + replay cache) and
// delivers the plain v2c notification to the manager's trap sink. An
// inbound INFORM must additionally be answered by the manager with a v3
// GetResponse RESP frame back through the pipe.
func TestChainAgentNotifToManagerSink(t *testing.T) {
	// manager-side trap sink
	sinkAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp", sinkAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// start the chain with the manager's sink pre-wired; handleTunnelNotif
	// is driven synchronously on the test goroutine, so setting m.sink
	// before that call is race-free (Run's select only touches it in
	// handleTunnelNotif, which the test owns here).
	h := startChain(t, nil)
	m := h.mgr
	m.sink = sink.LocalAddr()

	// a v2c trap PDU the agent side wraps for its local devices
	oidBytes, err := msg.EncodeOID("1.3.6.1.6.3.1.1.5.1")
	if err != nil {
		t.Fatal(err)
	}
	var vbs []byte
	vbs = appendBinding(vbs, msg.OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
	vbs = appendBinding(vbs, msg.OIDSnmpTrapOID, 0x06, oidBytes)
	trapPDU := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vbs)

	// the agent side wraps it into v3 authPriv for the manager (own engine
	// state, salt counter, signing — the same crypto path its trap engine
	// uses) and sends it as NOTIF
	scoped := msg.BuildScoped(h.agt.clock.EngineID(), []byte{}, trapPDU)
	notif, err := buildAgentNotif(t, h.agt, scoped)
	if err != nil {
		t.Fatal(err)
	}
	f := &tunnel.Frame{Type: tunnel.TypeNOTIF, CorrID: 1, Payload: notif}
	m.handleTunnelNotif(f)

	sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatalf("manager sink never received the agent-side trap: %v", err)
	}
	ver, comm, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("undecodable sink trap: %v", err)
	}
	if ver != msg.Version2c || string(comm) != "public" {
		t.Fatalf("bad sink trap version/community: %d %q", ver, comm)
	}
	if fields, ok := pduCommon(pdu); !ok || fields.ReqID != 0 {
		t.Fatalf("bad sink trap PDU: ok=%v", ok)
	}
}

// TestChainAgentInformResponse pins the manager's inform-response path: an
// agent-originated v3 INFORM (PDUInformRequest inside a NOTIF frame) is
// verified/unwrapped by the manager, delivered to the manager's clear v2c
// sink, and answered with a v3 GetResponse RESP frame (FlagInform, tunnel
// corrID preserved) back through the pipe toward the agent side.
func TestChainAgentInformResponse(t *testing.T) {
	h := startChain(t, nil)
	m := h.mgr

	// the manager's inform response lands on the agent-side pipe end as a
	// RESP frame (subscribe before triggering so nothing is lost; the pipe
	// channel is buffered)
	respCh, cancel := h.pipe.peer.Subscribe(tunnel.TypeRESP)
	defer cancel()

	// manager-side clear v2c sink
	sinkAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp", sinkAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	m.sink = sink.LocalAddr()

	// build the agent-originated inform: PDUInformRequest (req-id 888)
	// with sysUpTime + snmpTrapOID, wrapped into v3 authPriv NOTIF with
	// the agent's own engine state and keys
	oidBytes, err := msg.EncodeOID("1.3.6.1.6.3.1.1.5.1")
	if err != nil {
		t.Fatal(err)
	}
	var vbs []byte
	vbs = appendBinding(vbs, msg.OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
	vbs = appendBinding(vbs, msg.OIDSnmpTrapOID, 0x06, oidBytes)
	informPDU := msg.BuildPDU(msg.PDUInformRequest, 888, 0, 0, vbs)
	scoped := msg.BuildScoped(h.agt.clock.EngineID(), []byte{}, informPDU)
	notif, err := buildAgentNotif(t, h.agt, scoped)
	if err != nil {
		t.Fatal(err)
	}
	m.handleTunnelNotif(&tunnel.Frame{Type: tunnel.TypeNOTIF, CorrID: 42, Payload: notif})

	// the clear v2c inform must reach the manager's sink
	sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatalf("manager sink never received the agent-side inform: %v", err)
	}
	ver, comm, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("undecodable sink inform: %v", err)
	}
	if ver != msg.Version2c || string(comm) != "public" {
		t.Fatalf("bad sink inform version/community: %d %q", ver, comm)
	}
	if fields, ok := pduCommon(pdu); !ok || fields.ReqID != 888 {
		t.Fatalf("bad sink inform PDU: ok=%v reqID=%d", ok, fields.ReqID)
	}

	// the inform response must come back as a RESP frame: FlagInform set,
	// corrID preserved, a v3 GetResponse echoing the inform's req-id
	select {
	case fr := <-respCh:
		if fr.Flags&tunnel.FlagInform == 0 {
			t.Fatalf("inform response frame missing FlagInform (flags %#x)", fr.Flags)
		}
		if fr.CorrID != 42 {
			t.Fatalf("inform response corrID %d, want 42", fr.CorrID)
		}
		m2, err := msg.ParseV3(fr.Payload)
		if err != nil {
			t.Fatalf("undecodable inform response: %v", err)
		}
		profiles, err := m.keys.profilesFor(h.agt.clock.EngineID())
		if err != nil {
			t.Fatal(err)
		}
		_, plain, err := unwrapV3(profiles, m2, fr.Payload)
		if err != nil {
			t.Fatalf("inform response failed verification: %v", err)
		}
		if len(plain) == 0 || plain[0] != msg.PDUGetResponse {
			t.Fatalf("inform response is not a GetResponse (tag %#x)", plain[0])
		}
		fields, ok := pduCommon(plain)
		if !ok {
			t.Fatal("undecodable inform response PDU")
		}
		if fields.ReqID != 888 {
			t.Fatalf("inform response req-id %d, want 888 (echoed)", fields.ReqID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no inform response frame for the agent side")
	}
}

// TestChainTrapFilter pins notification filtering on the manager-side trap
// ingress through the full chain: allowed traps reach the agent-side sink,
// denied traps never leave the manager side.
func TestChainTrapFilter(t *testing.T) {
	filt, err := notifyfilter.New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		t.Fatal(err)
	}
	sinkAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp", sinkAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// start the chain with filter + trap sink pre-wired (before Run)
	h := startChainSink(t, filt, sink.LocalAddr().String())

	// establish engine state
	for i := 0; i < 3; i++ {
		if _, ok := h.clearGet(t, "public", "1.3.6.1.2.1.1.1.0"); ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	buildTrap := func(t *testing.T, trapOID string) []byte {
		t.Helper()
		oidBytes, err := msg.EncodeOID(trapOID)
		if err != nil {
			t.Fatal(err)
		}
		var vbs []byte
		vbs = appendBinding(vbs, msg.OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
		vbs = appendBinding(vbs, msg.OIDSnmpTrapOID, 0x06, oidBytes)
		trapPDU := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vbs)
		dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), trapPDU)
		if err != nil {
			t.Fatal(err)
		}
		return dg
	}

	// allowed trap (different enterprise subtree): reaches the sink
	h.mgr.handleClearTrap(buildTrap(t, "1.3.6.1.4.1.999.0.1"))
	sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	if _, _, err := sink.ReadFrom(buf); err != nil {
		t.Fatalf("allowed trap never reached the sink: %v", err)
	}

	// denied trap: nothing at the sink
	h.mgr.handleClearTrap(buildTrap(t, "1.3.6.1.4.1.99.0.7"))
	sink.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, _, err := sink.ReadFrom(buf); err == nil {
		t.Fatalf("denied trap reached the sink (%d bytes)", n)
	}

	// the listener must still be alive: another allowed trap arrives
	h.mgr.handleClearTrap(buildTrap(t, "1.3.6.1.4.1.999.0.2"))
	sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := sink.ReadFrom(buf); err != nil {
		t.Fatalf("trap listener died after a denial: %v", err)
	}
}

// TestChainInformRoundTrip pins the inform path end-to-end: a clear v2c
// inform from a device is wrapped into a v3 NOTIF (FlagInform, tracked by
// tunnel corrID), the agent side unwraps it, answers with a v3 GetResponse
// RESP frame, and the manager side translates that back into a clear v2c
// inform response for the device (same socket, matching req-id).
func TestChainInformRoundTrip(t *testing.T) {
	h := startChain(t, nil)

	// trap listener: informs arrive here, responses go back to the sender
	trapAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	trapConn, err := net.ListenUDP("udp", trapAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer trapConn.Close()

	// establish engine state (the inform path needs the remote engine)
	for i := 0; i < 3; i++ {
		if _, ok := h.clearGet(t, "public", "1.3.6.1.2.1.1.1.0"); ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// build a clear v2c inform: GET-like PDU with sysUpTime + snmpTrapOID
	oidBytes, err := msg.EncodeOID("1.3.6.1.6.3.1.1.5.1")
	if err != nil {
		t.Fatal(err)
	}
	var vbs []byte
	vbs = appendBinding(vbs, msg.OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
	vbs = appendBinding(vbs, msg.OIDSnmpTrapOID, 0x06, oidBytes)
	informPDU := msg.BuildPDU(msg.PDUInformRequest, 777, 0, 0, vbs)
	informDG, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), informPDU)
	if err != nil {
		t.Fatal(err)
	}

	// fire the inform at the manager's trap listener (Run must have bound
	// it: m.cfg.TrapListenAddr is not set in the harness, so drive the
	// ingress like readTraps does, stashing the sender address first)
	if info, perr := msg.Peek(informDG); perr == nil && msg.IsInform(info.PDUType) {
		h.mgr.informMu.Lock()
		h.mgr.lastInform = trapConn.LocalAddr()
		h.mgr.informMu.Unlock()
	}
	h.mgr.handleClearTrap(append([]byte{}, informDG...))

	// the clear inform response must come back to the trap socket
	trapConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := trapConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no inform response for the device: %v", err)
	}
	ver, comm, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("undecodable inform response: %v", err)
	}
	if ver != msg.Version2c || string(comm) != "public" {
		t.Fatalf("bad inform response version/community: %d %q", ver, comm)
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		t.Fatal("undecodable inform response PDU")
	}
	if fields.ReqID != 777 {
		t.Fatalf("inform response req-id %d, want 777 (device's req-id echoed)", fields.ReqID)
	}
}
