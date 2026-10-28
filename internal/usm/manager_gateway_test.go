// manager_gateway_test.go (package usm_test): end-to-end tests for the
// usm-manager-gateway mode (legacy manager → clear v1/v2c → gateway →
// v3 USM authPriv → real v3 agent). The fake v3 agent is built from the
// msg primitives (own engine: discovery Report responder, authPriv GET
// responder, inform originator) using the exact patterns the real-snmpd
// spike proved (spike_snmpd_test.go, -tags snmpd_spike): responses echo
// the request's v3 header msgID (the gateway correlates by header msgID),
// are signed+encrypted with keys localized to the agent's engineID, and
// the varbind-list content passed to BuildPDU stays RAW (BuildPDU wraps
// the 0x30 SEQUENCE itself).
package usm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"go.uber.org/zap"
)

const (
	fakeEngBoots = uint32(1)
	fakeEngTime  = uint32(1000)
)

// agentEvent is one datagram the fake v3 agent classified.
type agentEvent struct {
	pduType uint8
	reqID   int32
	vbs     []byte
}

// fakeV3Agent is a fake SNMPv3 authPriv agent: it answers RFC 3414
// discovery with an unsigned Report carrying its own engine state and
// authPriv requests with signed+encrypted responses (keys localized to
// its own engine). GetResponses arriving on its socket (the gateway's
// inform acks) are reported on acks, originator requests on saw.
type fakeV3Agent struct {
	conn  net.PacketConn
	addr  string
	eng   []byte
	profs *usm.Profiles
	saw   chan agentEvent
	acks  chan agentEvent
}

func startFakeV3Agent(t *testing.T) *fakeV3Agent {
	t.Helper()
	return startFakeV3AgentOn(t, "127.0.0.1:0")
}

// startFakeV3AgentOn binds the fake agent on an explicit address, so a
// scenario can put the v3 (agent) leg on IPv6.
func startFakeV3AgentOn(t *testing.T, bind string) *fakeV3Agent {
	t.Helper()
	conn, err := net.ListenPacket("udp", bind)
	if err != nil {
		t.Fatal(err)
	}
	engID := []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 0x01, 0xde, 0xad, 0xbe, 0xef}
	profs, err := usm.NewProfiles([]usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivAES,
		PrivPassphrase: "privpass",
	}}, engID)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeV3Agent{
		conn:  conn,
		addr:  conn.LocalAddr().String(),
		eng:   engID,
		profs: profs,
		saw:   make(chan agentEvent, 8),
		acks:  make(chan agentEvent, 8),
	}
	go a.loop()
	return a
}

func (a *fakeV3Agent) loop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		a.handle(append([]byte(nil), buf[:n]...), from)
	}
}

// handle classifies one datagram: discovery (Reportable, empty USM) gets
// an unsigned Report with our engine state; anything else is assumed to
// be an authenticated request (or the gateway's inform ack) and is
// unwrapped, answered, and reported.
func (a *fakeV3Agent) handle(dg []byte, from net.Addr) {
	m, err := msg.ParseV3(dg)
	if err != nil {
		return
	}
	// Discovery: Reportable flag, no user, no auth.
	if m.Header.MsgFlags&msg.MsgFlagReportable != 0 && m.USM.UserName == "" {
		pdu := msg.BuildPDU(msg.PDUReport, int32(m.Header.MsgID), 0, 0, nil)
		scoped := msg.BuildScoped(a.eng, []byte{}, pdu)
		out, err := msg.BuildV3(msg.V3Header{
			MsgID:      m.Header.MsgID,
			MsgMaxSize: msg.DefaultMsgMaxSize,
			MsgFlags:   msg.MsgFlagReportable,
			SecModel:   msg.SecurityModelUSM,
		}, msg.USMParams{
			EngineID: a.eng,
			Boots:    fakeEngBoots,
			Time:     fakeEngTime,
		}, scoped, nil)
		if err != nil {
			return
		}
		_, _ = a.conn.WriteTo(out, from)
		return
	}

	// Authenticated request: unwrap with our own localized keys.
	keys, perr := usm.NewProfilesFromSecurity(securityForAgentUser(), a.eng)
	if perr != nil {
		return
	}
	_, plain, err := usm.UnwrapV3(keys, m, dg)
	if err != nil {
		return
	}
	pduType, fields, perr := msg.ParsePDU(plain)
	if perr != nil {
		return
	}
	ev := agentEvent{pduType: pduType, reqID: fields.ReqID, vbs: fields.Varbinds}

	if msg.IsGetResponse(pduType) || msg.IsInform(pduType) {
		// The gateway's inform ack (GetResponse) or a peer inform —
		// report only, never answered by the fake agent itself.
		a.acks <- ev
		return
	}
	a.saw <- ev

	// Respond: signed+encrypted GetResponse echoing reqID + varbinds.
	respPDU := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
	scoped := msg.BuildScoped(a.eng, []byte{}, respPDU)
	uc, ok := keys.Lookup("proxy")
	if !ok {
		return
	}
	privParams := make([]byte, 8) // one-shot fake agent; salt value unchecked
	authParams := make([]byte, uc.Profile().AuthProtocol.MacLength())
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      m.Header.MsgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   a.eng,
		Boots:      fakeEngBoots,
		Time:       fakeEngTime,
		UserName:   "proxy",
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, func(plainPDU []byte) ([]byte, error) {
		return usm.EncryptScoped(uc.Profile().PrivProtocol, uc.PrivKey(), fakeEngBoots, fakeEngTime, privParams, plainPDU)
	})
	if err != nil {
		return
	}
	if err := usm.SignV3(out, uc.Profile().AuthProtocol, uc.AuthKey()); err != nil {
		return
	}
	_, _ = a.conn.WriteTo(out, from)
}

// securityForAgentUser mirrors the config the gateway is built with (the
// agent-side credentials must match on both ends).
func securityForAgentUser() config.Security {
	return config.Security{
		Mode: "usm-manager-gateway",
		Users: []config.UserCfg{{
			Name:           "proxy",
			AuthProtocol:   "sha",
			AuthPassphrase: "authpass",
			PrivProtocol:   "aes",
			PrivPassphrase: "privpass",
		}},
	}
}

// buildManagerGateway starts a ManagerGateway with a clear front leg on
// 127.0.0.1:front relaying to agentAddr over v3. trapListen/trapSink
// enable the reverse notification path when both are set. Returns the
// gateway and a stop func.
func buildManagerGateway(t *testing.T, front int, agentAddr, trapListen, trapSink string) (*usm.ManagerGateway, func()) {
	t.Helper()
	return buildManagerGatewayAt(t, net.JoinHostPort("127.0.0.1", itoa(front)), agentAddr, trapListen, trapSink)
}

// buildManagerGatewayAt is buildManagerGateway with an explicit clear front
// address (the v3 agent address was already a string).
func buildManagerGatewayAt(t *testing.T, frontAddr, agentAddr, trapListen, trapSink string) (*usm.ManagerGateway, func()) {
	t.Helper()

	cfg := config.GatewayRole{
		ListenAddr:        frontAddr,
		AgentAddr:         agentAddr,
		TrapListenAddr:    trapListen,
		TrapSinkAddr:      trapSink,
		TrapSinkCommunity: "managercomm",
	}

	gw, err := usm.NewManagerGateway(cfg, securityForAgentUser(), zap.NewNop(), observ.NewMetrics())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- gw.Run(done, ready)
		close(runErr)
	}()
	waitGatewayReady(t, ready, runErr)
	return gw, func() {
		close(done)
		select {
		case err, ok := <-runErr:
			if ok && err != nil {
				t.Errorf("manager gateway exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("manager gateway did not stop within 5 seconds")
		}
	}
}

// clearGet builds a clear v2c GET datagram for sysDescr.0.
func clearGet(t *testing.T, reqID int32) []byte {
	t.Helper()
	vb := msg.AppendTLV(msg.AppendTLV(nil, 0x06, mustOID(t, "1.3.6.1.2.1.1.1.0")), 0x05, []byte{})
	vbl := msg.AppendTLV(nil, 0x30, vb)
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0, vbl)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("managercomm"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	return dg
}

// parseClearResponse parses a clear v2c GetResponse datagram.
func parseClearResponse(t *testing.T, dg []byte) int32 {
	t.Helper()
	ver, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		t.Fatalf("SplitV1V2c: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("response version = %d, want v2c", ver)
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("ParsePDU: %v", err)
	}
	if !msg.IsGetResponse(pduType) {
		t.Fatalf("PDU type = 0x%x, want GetResponse", pduType)
	}
	return fields.ReqID
}

// buildV3Notification wraps a clear PDU into a signed+encrypted v3
// message from the fake agent's engine (the originator side of the
// reverse path).
func buildV3Notification(t *testing.T, agent *fakeV3Agent, msgID int64, pduType uint8, reqID int32, vbs []byte) []byte {
	t.Helper()
	pdu := msg.BuildPDU(pduType, reqID, 0, 0, vbs)
	scoped := msg.BuildScoped(agent.eng, []byte{}, pdu)
	uc, ok := agent.profs.Lookup("proxy")
	if !ok {
		t.Fatal("fake agent profile missing")
	}
	authParams := make([]byte, uc.Profile().AuthProtocol.MacLength())
	privParams := make([]byte, 8)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(msgID),
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(msg.MsgFlagAuth | msg.MsgFlagPriv),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   agent.eng,
		Boots:      fakeEngBoots,
		Time:       fakeEngTime,
		UserName:   "proxy",
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, func(plain []byte) ([]byte, error) {
		return usm.EncryptScoped(uc.Profile().PrivProtocol, uc.PrivKey(), fakeEngBoots, fakeEngTime, privParams, plain)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := usm.SignV3(out, uc.Profile().AuthProtocol, uc.AuthKey()); err != nil {
		t.Fatal(err)
	}
	return out
}

// notifVarbinds builds a v2 notification varbind-list content with one
// linkDown-style OID and an empty value.
func notifVarbinds(t *testing.T) []byte {
	t.Helper()
	vb := msg.AppendTLV(msg.AppendTLV(nil, 0x06, mustOID(t, "1.3.6.1.6.3.1.1.5.1")), 0x05, []byte{})
	return msg.AppendTLV(nil, 0x30, vb)
}

// TestManagerGatewayDiscoveryAndGet: a legacy manager sends a clear v2c
// GET; the gateway discovers the agent's engine (fake Report), re-issues
// the request as v3 authPriv, and strips the verified response back to
// clear v2c with the manager's req-id echoed.
func TestManagerGatewayDiscoveryAndGet(t *testing.T) {
	const front = 12621
	frontAddr := net.JoinHostPort("127.0.0.1", itoa(front))

	agent := startFakeV3Agent(t)
	defer agent.conn.Close()

	_, stop := buildManagerGateway(t, front, agent.addr, "", "")
	defer stop()

	mgr, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	if _, err := mgr.WriteTo(clearGet(t, 4242), mustAddr(t, frontAddr)); err != nil {
		t.Fatal(err)
	}

	// The fake agent must have seen an authenticated GET (the v3 leg).
	select {
	case <-agent.saw:
	case <-time.After(5 * time.Second):
		t.Fatal("agent never saw the forwarded v3 GET")
	}

	// The manager gets a clear v2c GetResponse back, req-id echoed.
	mgr.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := mgr.ReadFrom(buf)
	if err != nil {
		t.Fatalf("manager read response: %v", err)
	}
	if reqID := parseClearResponse(t, buf[:n]); reqID != 4242 {
		t.Fatalf("response req-id = %d, want 4242 (echoed)", reqID)
	}
}

// TestManagerGatewayAgentTrapRelay: a v3 trap from the agent is verified,
// unwrapped and relayed as a clear v2c trap to the manager's trap
// receiver (TrapSinkAddr, community = trap_sink_community).
func TestManagerGatewayAgentTrapRelay(t *testing.T) {
	const front = 12622
	trapListen := freeUDPPort(t)

	agent := startFakeV3Agent(t)
	defer agent.conn.Close()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	_, stop := buildManagerGateway(t, front, agent.addr, trapListen, sink.LocalAddr().String())
	defer stop()

	out := buildV3Notification(t, agent, 500, msg.PDUSNMPv2Trap, 0, notifVarbinds(t))

	// Send the trap from an ephemeral socket toward the trap listener.
	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.WriteTo(out, mustAddr(t, trapListen)); err != nil {
		t.Fatal(err)
	}

	// The trap sink sees the clear v2c relay.
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatalf("trap sink read: %v", err)
	}
	ver, comm, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("relay SplitV1V2c: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("relay version = %d, want v2c", ver)
	}
	if string(comm) != "managercomm" {
		t.Fatalf("relay community = %q, want managercomm", comm)
	}
	pduType, _, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("relay ParsePDU: %v", err)
	}
	if pduType != msg.PDUSNMPv2Trap {
		t.Fatalf("relay PDU type = 0x%x, want v2 trap", pduType)
	}
}

// TestManagerGatewayAgentInform: a v3 inform from the agent is answered
// directly by the gateway (v3 GetResponse back toward the agent, req-id
// echoed) and its payload is relayed as a clear v2 trap to the manager's
// trap receiver.
func TestManagerGatewayAgentInform(t *testing.T) {
	const front = 12623
	trapListen := freeUDPPort(t)

	agent := startFakeV3Agent(t)
	defer agent.conn.Close()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	_, stop := buildManagerGateway(t, front, agent.addr, trapListen, sink.LocalAddr().String())
	defer stop()

	out := buildV3Notification(t, agent, 600, msg.PDUInformRequest, 777, notifVarbinds(t))

	// The inform is sent toward the trap listener from an ephemeral
	// socket. The confirmation must come back to THAT socket: a sender
	// that uses a connected UDP socket (gosnmp, pysnmp, plenty of agents)
	// has the kernel discard an answer from any other source address, so
	// replying toward the configured AgentAddr only works when the sender
	// happens to be the agent and happens to use its service port.
	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.WriteTo(out, mustAddr(t, trapListen)); err != nil {
		t.Fatal(err)
	}

	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := src.ReadFrom(buf)
	if err != nil {
		t.Fatalf("inform sender never saw its ack: %v", err)
	}
	m, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("ack is not a v3 message: %v", err)
	}
	keys, err := usm.NewProfilesFromSecurity(securityForAgentUser(), agent.eng)
	if err != nil {
		t.Fatal(err)
	}
	_, plain, err := usm.UnwrapV3(keys, m, buf[:n])
	if err != nil {
		t.Fatalf("ack rejected by the sender's own keys: %v", err)
	}
	pduType, fields, err := msg.ParsePDU(plain)
	if err != nil {
		t.Fatalf("ack PDU: %v", err)
	}
	if !msg.IsGetResponse(pduType) {
		t.Fatalf("ack PDU type = 0x%x, want GetResponse", pduType)
	}
	if fields.ReqID != 777 {
		t.Fatalf("ack req-id = %d, want 777 (echoed)", fields.ReqID)
	}

	// And the payload is relayed as a clear v2 trap to the trap sink.
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	sinkBuf := make([]byte, 65536)
	sn, _, err := sink.ReadFrom(sinkBuf)
	if err != nil {
		t.Fatalf("trap sink read: %v", err)
	}
	relayType, _, err := msg.ParsePDU(mustPDUTLV(t, sinkBuf[:sn]))
	if err != nil || relayType != msg.PDUSNMPv2Trap {
		t.Fatalf("relay PDU type = 0x%x (err %v), want v2 trap", relayType, err)
	}
}

// TestManagerGatewayBadDigest: a tampered v3 trap (one flipped byte in
// the ciphertext) must be dropped silently — no clear relay, listener
// stays alive.
func TestManagerGatewayBadDigest(t *testing.T) {
	const front = 12624
	trapListen := freeUDPPort(t)

	agent := startFakeV3Agent(t)
	defer agent.conn.Close()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	_, stop := buildManagerGateway(t, front, agent.addr, trapListen, sink.LocalAddr().String())
	defer stop()

	out := buildV3Notification(t, agent, 700, msg.PDUSNMPv2Trap, 0, notifVarbinds(t))
	out[len(out)-3] ^= 0xFF // flip a byte inside the encrypted scopedPDU

	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.WriteTo(out, mustAddr(t, trapListen)); err != nil {
		t.Fatal(err)
	}

	// No clear relay may arrive; the trap listener must stay alive.
	sink.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 65536)
	n, _, err := sink.ReadFrom(buf)
	if err == nil {
		t.Fatalf("tampered trap was relayed (%d bytes) — digest check failed", n)
	}
	if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
		t.Fatalf("sink read error (want timeout): %v", err)
	}
}

// mustPDUTLV extracts the raw PDU TLV from a clear v2c datagram.
func mustPDUTLV(t *testing.T, dg []byte) []byte {
	t.Helper()
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		t.Fatalf("SplitV1V2c: %v", err)
	}
	return pdu
}

// mustAddr resolves a host:port string (test helper).
func mustAddr(t *testing.T, addr string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestManagerGatewayCompliantInform pins the RFC 3414 rule that the
// RECEIVER of a confirmed notification is the authoritative engine.
//
// A compliant sender (net-snmp, pysnmp, node) first probes for our engine,
// then builds the inform with OUR engineID and keys localized to it, and
// keeps its own contextEngineID. Our answer has to be a response in every
// detail: the probe's msgID echoed back, no Reportable flag, the request's
// contextEngineID, and the same engine state we announced. gosnmp skips
// the discovery handshake and accepts a sloppy answer, so only this test
// (and the vendor matrix) catches the difference.
func TestManagerGatewayCompliantInform(t *testing.T) {
	const front = 12630
	trapListen := freeUDPPort(t)

	agent := startFakeV3Agent(t)
	defer agent.conn.Close()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	_, stop := buildManagerGateway(t, front, agent.addr, trapListen, sink.LocalAddr().String())
	defer stop()

	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	trapAddr := mustAddr(t, trapListen)

	// 1. Discovery probe, exactly the shape a vendor sender emits:
	// Reportable|NoAuthNoPriv, empty user/engine, empty GET.
	probePDU := msg.BuildPDU(msg.PDUGetRequest, 1234, 0, 0, nil)
	probe, err := msg.BuildV3(msg.V3Header{
		MsgID:      4242,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{}, msg.BuildScoped([]byte{0x80, 0, 0x1f, 0x88, 0x80, 9}, []byte{}, probePDU), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.WriteTo(probe, trapAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := src.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no discovery Report: %v", err)
	}
	report, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("Report is not v3: %v", err)
	}
	if report.Header.MsgID != 4242 {
		t.Fatalf("Report msgID = %d, want the probe's 4242", report.Header.MsgID)
	}
	if report.Header.MsgFlags&(msg.MsgFlagAuth|msg.MsgFlagPriv) != 0 {
		t.Fatalf("Report flags = %#x, want NoAuthNoPriv", report.Header.MsgFlags)
	}
	if len(report.USM.EngineID) == 0 {
		t.Fatal("Report carries no authoritative engine ID")
	}
	if pduType, _, perr := msg.ParsePDU(report.PDU); perr != nil || pduType != msg.PDUReport {
		t.Fatalf("Report PDU type = 0x%02x (err %v), want a Report", pduType, perr)
	}

	engineID := report.USM.EngineID
	boots, etime := report.USM.Boots, report.USM.Time

	// 2. The inform: addressed to the discovered engine, keys localized
	// to it, but with the originator's own contextEngineID.
	authKey, err := usm.PasswordToKey(usm.AuthSHA, "authpass", string(engineID))
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := usm.LocalizedPrivKey(usm.AuthSHA, usm.PrivAES, "privpass", string(engineID))
	if err != nil {
		t.Fatal(err)
	}
	originatorID := []byte{0x80, 0, 0x1f, 0x88, 0x80, 7, 7, 7, 7, 7, 7}
	privParams := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	authParams := make([]byte, usm.AuthSHA.MacLength())

	informPDU := msg.BuildPDU(msg.PDUInformRequest, 777, 0, 0, notifVarbinds(t))
	scoped := msg.BuildScoped(originatorID, []byte{}, informPDU)
	inform, err := msg.BuildV3(msg.V3Header{
		MsgID:      5150,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(msg.MsgFlagReportable | msg.MsgFlagAuth | msg.MsgFlagPriv),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   engineID,
		Boots:      boots,
		Time:       etime,
		UserName:   "proxy",
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, func(plain []byte) ([]byte, error) {
		return usm.EncryptScoped(usm.PrivAES, privKey, boots, etime, privParams, plain)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := usm.SignV3(inform, usm.AuthSHA, authKey); err != nil {
		t.Fatal(err)
	}
	if _, err := src.WriteTo(inform, trapAddr); err != nil {
		t.Fatal(err)
	}

	// 3. The confirmation, judged the way a vendor judges it.
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = src.ReadFrom(buf)
	if err != nil {
		t.Fatalf("inform was not confirmed: %v", err)
	}
	ack, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("confirmation is not v3: %v", err)
	}
	if ack.Header.MsgID != 5150 {
		t.Fatalf("confirmation msgID = %d, want the inform's 5150 (it is the transaction id)", ack.Header.MsgID)
	}
	if ack.Header.MsgFlags&msg.MsgFlagReportable != 0 {
		t.Fatalf("confirmation has the Reportable flag set (flags %#x): a response is unconfirmed class", ack.Header.MsgFlags)
	}
	if ack.Header.MsgFlags&(msg.MsgFlagAuth|msg.MsgFlagPriv) != msg.MsgFlagAuth|msg.MsgFlagPriv {
		t.Fatalf("confirmation flags = %#x, want authPriv", ack.Header.MsgFlags)
	}
	if string(ack.USM.EngineID) != string(engineID) {
		t.Fatalf("confirmation engine = %x, want the discovered %x", ack.USM.EngineID, engineID)
	}
	keys, err := usm.NewProfilesFromSecurity(securityForAgentUser(), engineID)
	if err != nil {
		t.Fatal(err)
	}
	_, plain, err := usm.UnwrapV3(keys, ack, buf[:n])
	if err != nil {
		t.Fatalf("confirmation does not verify/decrypt with the announced keys: %v", err)
	}
	if string(ack.ContextEngineID) != string(originatorID) {
		t.Fatalf("confirmation contextEngineID = %x, want the request's %x", ack.ContextEngineID, originatorID)
	}
	pduType, fields, err := msg.ParsePDU(plain)
	if err != nil {
		t.Fatalf("confirmation PDU: %v", err)
	}
	if !msg.IsGetResponse(pduType) || fields.ReqID != 777 {
		t.Fatalf("confirmation PDU type/req-id = 0x%02x/%d, want GetResponse/777", pduType, fields.ReqID)
	}

	// 4. And the payload reached the legacy manager as a clear v2 trap.
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	sinkBuf := make([]byte, 65536)
	sn, _, err := sink.ReadFrom(sinkBuf)
	if err != nil {
		t.Fatalf("trap sink read: %v", err)
	}
	if typ, _, perr := msg.ParsePDU(mustPDUTLV(t, sinkBuf[:sn])); perr != nil || typ != msg.PDUSNMPv2Trap {
		t.Fatalf("relay PDU type = 0x%02x (err %v), want v2 trap", typ, perr)
	}
}
