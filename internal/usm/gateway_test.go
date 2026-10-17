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
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/cache"
	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/usm"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// buildGateway starts a GatewayTranslator on 127.0.0.1:front relaying to
// 127.0.0.1:agent; trapListen/trapSink enable the trap listener when set.
func buildGateway(t *testing.T, front, agent int, trapListen, trapSink string) (stop func()) {
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
		ListenAddr:     net.JoinHostPort("127.0.0.1", itoa(front)),
		AgentAddr:      net.JoinHostPort("127.0.0.1", itoa(agent)),
		TrapListenAddr: trapListen,
		TrapSinkAddr:   trapSink,
		AgentCommunity: "realcomm",
	}
	users := []usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}

	tr, err := usm.NewGatewayTranslator(cfg, users, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = tr.Run(done) }()
	return func() { close(done) }
}

// waitBound blocks until addr is bound by someone else (our probe bind
// fails) — removes the startup race against the translator's Run.
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
	waitBound(t, frontAddr)

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
	waitBound(t, frontAddr)

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
	waitBound(t, frontAddr)

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
	waitBound(t, trapListen)

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
