// gateway_test.go (package usm_test): end-to-end tests for the single-box
// USM gateway. A gosnmp v3 authPriv client speaks standard SNMP directly
// to the gateway's plain-UDP front leg (no shim, no tunnel): gosnmp
// performs RFC 3414 engine discovery against our Report, then issues
// authPriv GETs which the gateway relays as clear v2c to a fake legacy
// agent. A gosnmp TrapListener validates the gateway's wrapped v3 trap
// notifications (digest + decrypt) as an independent implementation.
package usm_test

import (
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// buildGateway starts a GatewayTranslator on 127.0.0.1:front relaying to
// 127.0.0.1:agent; trapListen/trapSink enable the trap listener when set.
// front=agent=0 starts a notification-only gateway (no request path).
// Optional trailing filters are passed to the translator.
func buildGateway(t *testing.T, front, agent int, trapListen, trapSink string, filt ...*notifyfilter.Filter) (stop func()) {
	t.Helper()

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.GatewayRole{
		TrapListenAddr: trapListen,
		TrapSinkAddr:   trapSink,
		AgentCommunity: "realcomm",
	}
	if front != 0 {
		cfg.ListenAddr = net.JoinHostPort("127.0.0.1", itoa(front))
		cfg.AgentAddr = net.JoinHostPort("127.0.0.1", itoa(agent))
	}
	users := []usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}

	tr, err := usm.NewGatewayTranslator(cfg, users, clock, zap.NewNop(), nil, filt...)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- tr.Run(done, ready)
		close(runErr)
	}()
	waitGatewayReady(t, ready, runErr)
	return func() {
		close(done)
		select {
		case err, ok := <-runErr:
			if ok && err != nil {
				t.Errorf("gateway exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("gateway did not stop within 5 seconds")
		}
	}
}

// waitGatewayReady waits for an explicit readiness signal and propagates an
// early Run error. Binding a probe socket to test readiness races with the
// gateway's own bind on Darwin.
func waitGatewayReady(t *testing.T, ready <-chan struct{}, runErr <-chan error) {
	t.Helper()
	select {
	case <-ready:
		return
	case err, ok := <-runErr:
		if !ok {
			t.Fatal("gateway exited during startup without an error")
		}
		t.Fatalf("gateway exited during startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for gateway startup")
	}
}

// recAgent is a fake legacy agent that records every datagram it receives
// and answers v2c GETs with an echo varbind (like fakeAgent).
type recAgent struct {
	conn net.PacketConn
	got  chan int
}

func newRecAgent(t *testing.T, addr string) *recAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ra := &recAgent{conn: conn, got: make(chan int, 16)}
	go ra.loop()
	return ra
}

func (r *recAgent) loop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case r.got <- n:
		default:
		}
		dg := append([]byte(nil), buf[:n]...)
		info, err := msg.Peek(dg)
		if err != nil || !msg.IsGet(info.PDUType) {
			continue
		}
		_, _, pdu, err := msg.SplitV1V2c(dg)
		if err != nil {
			continue
		}
		_, fields, err := msg.ParsePDU(pdu)
		if err != nil {
			continue
		}
		resp := msg.BuildPDU(msg.PDUGetResponse, info.RequestID, 0, 0, fields.Varbinds)
		out, err := msg.BuildV1V2c(msg.Version2c, []byte("realcomm"), resp)
		if err != nil {
			continue
		}
		_, _ = r.conn.WriteTo(out, addr)
	}
}

func (r *recAgent) close() { r.conn.Close() }

// freeUDPPort returns a free 127.0.0.1 UDP address (bound then released).
func freeUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
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

// TestGatewayDiscoveryAndGet: gosnmp performs engine discovery (our
// unsigned Report reveals engineID/boots/time), then issues an authPriv
// GET which the gateway relays as clear v2c to the fake agent; the
// response comes back as a signed+encrypted v3 response gosnmp verifies.
func TestGatewayDiscoveryAndGet(t *testing.T) {
	const front, agent = 12611, 11711
	frontAddr := net.JoinHostPort("127.0.0.1", itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	stop := buildGateway(t, front, agent, "", "")
	defer stop()

	g := gosnmpV3Client(t, frontAddr)
	defer g.Conn.Close()

	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("v3 GET through gateway: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("expected 1 varbind, got %d", len(result.Variables))
	}
	if result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("wrong OID echoed: %s", result.Variables[0].Name)
	}
}

// TestGatewayWrongUser: an authPriv request with an unknown user must be
// rejected (Report with usmStatsUnknownUserNames), never forwarded.
func TestGatewayWrongUser(t *testing.T) {
	const front, agent = 12612, 11712
	frontAddr := net.JoinHostPort("127.0.0.1", itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	stop := buildGateway(t, front, agent, "", "")
	defer stop()

	g := gosnmpV3Client(t, frontAddr)
	defer g.Conn.Close()
	g.SecurityParameters = &gosnmp.UsmSecurityParameters{
		UserName:                 "nobody",
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: "authpass",
		PrivacyProtocol:          gosnmp.AES,
		PrivacyPassphrase:        "privpass",
	}

	_, err = g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
}

// TestGatewayClearRejected: clear v2c arriving on the v3 front leg must
// be rejected — nothing reaches the legacy agent and nothing comes back.
// The control at the end proves the path itself is alive.
func TestGatewayClearRejected(t *testing.T) {
	const front, agent = 12613, 11713
	frontAddr := net.JoinHostPort("127.0.0.1", itoa(front))

	ra := newRecAgent(t, net.JoinHostPort("127.0.0.1", itoa(agent)))
	defer ra.close()

	stop := buildGateway(t, front, agent, "", "")
	defer stop()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()

	pdu := msg.BuildPDU(msg.PDUGetRequest, 42, 0, 0, []byte{})
	clear, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	gaddr, _ := net.ResolveUDPAddr("udp", frontAddr)
	if _, err := probe.WriteTo(clear, gaddr); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-ra.got:
		t.Fatalf("clear SNMP was forwarded to the legacy agent (%d bytes)", n)
	case <-time.After(300 * time.Millisecond):
	}
	if err := probe.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	if n, _, err := probe.ReadFrom(buf); err == nil {
		t.Fatalf("clear SNMP elicited a response (%d bytes), want rejection silence", n)
	}

	// control: an authenticated v3 GET does traverse the gateway.
	g := gosnmpV3Client(t, frontAddr)
	defer g.Conn.Close()
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("v3 GET control failed: %v", err)
	}
	select {
	case <-ra.got:
	case <-time.After(2 * time.Second):
		t.Fatal("v3 GET never reached the agent")
	}
}

// TestGatewayTrapDirection: a legacy device fires a clear v1 trap at the
// gateway's trap listener; the gateway wraps it into an authenticated v3
// USM notification for the manager's trap receiver — validated here by a
// gosnmp TrapListener (independent implementation: digest verification
// against our engine ID + AES decryption of the scopedPDU).
func TestGatewayTrapDirection(t *testing.T) {
	const front, agent = 12614, 11714
	sinkAddr := freeUDPPort(t)
	trapListen := freeUDPPort(t)

	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		Logger:        gosnmp.NewLogger(log.New(os.Stderr, "TRAPL ", 0)),
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "proxy",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        "privpass",
		},
	}
	trapGot := make(chan *gosnmp.SnmpPacket, 4)
	tl.OnNewTrap = func(s *gosnmp.SnmpPacket, u *net.UDPAddr) {
		trapGot <- s
	}
	go func() { _ = tl.Listen(sinkAddr) }()
	defer tl.Close()
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener never came up")
	}

	stop := buildGateway(t, front, agent, trapListen, sinkAddr)
	defer stop()

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
	case s := <-trapGot:
		if s.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", s.Version)
		}
		sp, ok := s.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok {
			t.Fatal("no USM security parameters on wrapped trap")
		}
		if sp.UserName != "proxy" {
			t.Fatalf("wrapped trap user = %q, want proxy", sp.UserName)
		}
		if len(s.Variables) == 0 {
			t.Fatal("wrapped trap has no varbinds")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped v3 trap never reached the sink")
	}
}

// TestGatewayTrapFiltered: with a deny filter for an enterprise prefix,
// a device trap inside the prefix never reaches the sink while traps
// outside it do; the listener stays alive for subsequent traps.
func TestGatewayTrapFiltered(t *testing.T) {
	const front, agent = 12615, 11715
	sinkAddr := freeUDPPort(t)
	trapListen := freeUDPPort(t)

	filt, err := notifyfilter.New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		t.Fatal(err)
	}

	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
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
	trapGot := make(chan string, 8)
	tl.OnNewTrap = func(s *gosnmp.SnmpPacket, u *net.UDPAddr) {
		// Record the snmpTrapOID.0 value (the enterprise-specific trap
		// OID); gosnmp decodes OID varbinds as dotted strings with a
		// leading dot.
		for _, v := range s.Variables {
			if v.Type == gosnmp.ObjectIdentifier {
				if oid, ok := v.Value.(string); ok {
					trapGot <- strings.TrimPrefix(oid, ".")
					return
				}
			}
		}
		trapGot <- ""
	}
	go func() { _ = tl.Listen(sinkAddr) }()
	defer tl.Close()
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener never came up")
	}

	stop := buildGateway(t, front, agent, trapListen, sinkAddr, filt)
	defer stop()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)

	// device fires a clear v1 enterpriseSpecific(6) trap
	sendTrap := func(ent string, spec int32) {
		t.Helper()
		trapPDU := msg.BuildV1Trap(msg.V1Trap{
			Enterprise: mustOID(t, ent),
			AgentAddr:  []byte{10, 0, 0, 1},
			Generic:    6,
			Specific:   spec,
			Timestamp:  12345,
			Varbinds:   []byte{},
		})
		trap, err := msg.BuildV1V2c(msg.Version1, []byte("devicecomm"), trapPDU)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(trap, laddr); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Allowed trap arrives (enterprise outside the deny prefix).
	sendTrap("1.3.6.1.4.1.999", 1)
	select {
	case got := <-trapGot:
		if want := "1.3.6.1.4.1.999.0.1"; got != want {
			t.Fatalf("first trap OID = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("allowed trap never reached the sink")
	}

	// 2. Denied trap never arrives; 3. a second allowed trap arrives.
	sendTrap("1.3.6.1.4.1.99", 7)
	sendTrap("1.3.6.1.4.1.999", 2)
	drain := time.After(700 * time.Millisecond)
	for {
		select {
		case got := <-trapGot:
			if got == "1.3.6.1.4.1.99.0.7" {
				t.Fatal("denied trap reached the sink")
			}
			if got == "1.3.6.1.4.1.999.0.2" {
				return // listener alive, denied trap absent
			}
		case <-drain:
			t.Fatal("second allowed trap never reached the sink (listener broken?)")
		}
	}
}

// startManagerSink starts a gosnmp TrapListener as the manager's v3 trap
// receiver. Returns the sink address and a channel of received packets.
// For informs the TrapListener auto-responds like a real manager
// (GetResponse signed with its own keys) — the inform round-trip oracle.
func startManagerSink(t *testing.T) (string, chan *gosnmp.SnmpPacket) {
	t.Helper()
	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
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
	trapGot := make(chan *gosnmp.SnmpPacket, 8)
	tl.OnNewTrap = func(s *gosnmp.SnmpPacket, u *net.UDPAddr) {
		trapGot <- s
	}
	sinkAddr := freeUDPPort(t)
	go func() { _ = tl.Listen(sinkAddr) }()
	t.Cleanup(tl.Close)
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener never came up")
	}
	return sinkAddr, trapGot
}

// deviceConn returns a UDP socket for firing clear notifications at the
// gateway's trap listener.
func deviceConn(t *testing.T, trapListen string) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// buildVBS builds a raw varbind-list (SEQUENCE content) with one varbind:
// snmpTrapOID.0 = oid (test helper; BuildPDU takes the raw list content).
func buildVBS(t *testing.T, oid string) []byte {
	t.Helper()
	oidTLV := msg.AppendTLV(nil, 0x06, mustOID(t, oid))
	snmpTrapOIDTLV := msg.AppendTLV(nil, 0x06, msg.OIDSnmpTrapOID)
	return msg.AppendTLV(nil, 0x30, append(append([]byte{}, snmpTrapOIDTLV...), oidTLV...))
}

// TestGatewayTrapRelay: a clear v2c device trap is wrapped into an
// authenticated+encrypted v3 notification and validated by the gosnmp
// TrapListener sink (notification-only gateway shape, no request path).
func TestGatewayTrapRelay(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildGateway(t, 0, 0, trapListen, sinkAddr)
	defer stop()

	vbs := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, buildVBS(t, "1.3.6.1.4.1.9999.1"))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case s := <-trapGot:
		if s.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", s.Version)
		}
		sp, ok := s.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok {
			t.Fatal("no USM security parameters on wrapped trap")
		}
		if sp.UserName != "proxy" {
			t.Fatalf("wrapped trap user = %q, want proxy", sp.UserName)
		}
		if len(s.Variables) == 0 {
			t.Fatal("wrapped trap has no varbinds")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped v3 trap never reached the sink")
	}
}

// TestGatewayInformRoundTrip: a clear v2c device inform is wrapped into a
// v3 inform; the gosnmp TrapListener auto-responds (GetResponse signed
// with the sink's own keys); the gateway verifies/decrypts the response
// and relays a clear v2c response back to the device (req-id and
// community echoed).
func TestGatewayInformRoundTrip(t *testing.T) {
	sinkAddr, _ := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildGateway(t, 0, 0, trapListen, sinkAddr)
	defer stop()

	const reqID = int32(777)
	vbs := msg.BuildPDU(msg.PDUInformRequest, reqID, 0, 0, buildVBS(t, "1.3.6.1.4.1.9999.1"))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	// the clear response must come back to this socket
	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("clear inform response never came back: %v", err)
	}
	ver, community, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("response undecodable: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("response version = %d, want 2c", ver)
	}
	if string(community) != "devicecomm" {
		t.Fatalf("response community = %q, want devicecomm", community)
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("response PDU undecodable: %v", err)
	}
	if pduType != msg.PDUGetResponse {
		t.Fatalf("response PDU type = 0x%02x, want GetResponse", pduType)
	}
	if fields.ReqID != reqID {
		t.Fatalf("response req-id = %d, want %d", fields.ReqID, reqID)
	}
}

// TestGatewayV1TrapNotif: a clear v1 trap is translated (RFC 2576) and
// wrapped like a v2c one.
func TestGatewayV1TrapNotif(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildGateway(t, 0, 0, trapListen, sinkAddr)
	defer stop()

	trapPDU := msg.BuildV1Trap(msg.V1Trap{
		Enterprise: mustOID(t, "1.3.6.1.4.1.9999"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    0,
		Specific:   0,
		Timestamp:  12345,
		Varbinds:   []byte{},
	})
	dg, err := msg.BuildV1V2c(msg.Version1, []byte("devicecomm"), trapPDU)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case s := <-trapGot:
		if s.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", s.Version)
		}
		if len(s.Variables) == 0 {
			t.Fatal("wrapped v1 trap has no varbinds (v2 translation failed)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped v1 trap never reached the sink")
	}
}

// TestGatewayNotifFilter: with a deny filter for an enterprise prefix,
// device traps inside the prefix never reach the sink while traps outside
// it do; the listener stays alive for subsequent traps.
func TestGatewayNotifFilter(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	filt, err := notifyfilter.New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		t.Fatal(err)
	}
	stop := buildGateway(t, 0, 0, trapListen, sinkAddr, filt)
	defer stop()

	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	conn := deviceConn(t, trapListen)
	fire := func(oid string) {
		t.Helper()
		vbs := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, buildVBS(t, oid))
		dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(dg, laddr); err != nil {
			t.Fatal(err)
		}
	}

	fire("1.3.6.1.4.1.99.7")  // denied
	fire("1.3.6.1.4.1.999.1") // allowed

	select {
	case <-trapGot:
	case <-time.After(5 * time.Second):
		t.Fatal("allowed trap never reached the sink")
	}
	// drain: no second packet may arrive (the denied one was dropped)
	select {
	case s := <-trapGot:
		t.Fatalf("denied trap reached the sink: %d varbinds", len(s.Variables))
	case <-time.After(700 * time.Millisecond):
	}
	// the listener must still be alive
	fire("1.3.6.1.4.1.999.2")
	select {
	case <-trapGot:
	case <-time.After(5 * time.Second):
		t.Fatal("listener dead after denial")
	}
}
