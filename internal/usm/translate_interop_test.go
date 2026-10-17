// translate_interop_test.go (package usm_test): end-to-end interop tests
// against gosnmp as an independent SNMPv3 implementation. A gosnmp v3
// authPriv client speaks over UDP to a shim that plays the tunnel side
// (feeding datagrams into the agent translator and writing translator
// output back to gosnmp). gosnmp validates our discovery Report and our
// signed+encrypted v3 responses byte-for-byte.
package usm_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// shim implements usm.FrameSink: it plays the tunnel side for the
// agent-side translator in tests (frames in/out, no DTLS).
type shim struct {
	mu   sync.Mutex
	subs map[uint8][]chan *tunnel.Frame
}

func newShim() *shim {
	return &shim{subs: make(map[uint8][]chan *tunnel.Frame)}
}

func (s *shim) Subscribe(ftype uint8) (<-chan *tunnel.Frame, func()) {
	ch := make(chan *tunnel.Frame, 64)
	s.mu.Lock()
	s.subs[ftype] = append(s.subs[ftype], ch)
	s.mu.Unlock()
	return ch, func() {}
}

// deliver injects a frame as if it arrived from the tunnel.
func (s *shim) deliver(typ, flags uint8, corrID uint16, payload []byte) {
	s.mu.Lock()
	subs := append([]chan *tunnel.Frame(nil), s.subs[typ]...)
	s.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- &tunnel.Frame{Type: typ, Flags: flags, CorrID: corrID, Payload: append([]byte(nil), payload...)}:
		default:
		}
	}
}

// Send satisfies usm.FrameSink (translator output).
func (s *shim) Send(_ context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	s.deliver(typ, flags, corrID, payload)
	return nil
}

// bridge connects gosnmp UDP <-> the translator via the shim: datagrams
// from gosnmp arrive as REQ frames; translator RESP frames go back out as
// UDP datagrams to gosnmp's source address.
func bridge(sh *shim, conn net.PacketConn) {
	go func() {
		respCh, cancel := sh.Subscribe(2) // msgTypeRESP
		defer cancel()
		for f := range respCh {
			_, _ = conn.WriteTo(f.Payload, mgrAddr())
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		setPeer(addr)
		sh.deliver(1, 0, 0, buf[:n]) // msgTypeREQ
	}
}

// mgrAddr is gosnmp's address; the bridge rewrites it since UDP conn Read
// gives us the real peer (we track it from ReadFrom instead).
var lastPeer struct {
	mu   sync.Mutex
	addr net.Addr
}

func setPeer(a net.Addr) {
	lastPeer.mu.Lock()
	lastPeer.addr = a
	lastPeer.mu.Unlock()
}

func mgrAddr() net.Addr {
	lastPeer.mu.Lock()
	defer lastPeer.mu.Unlock()
	return lastPeer.addr
}

// buildTranslator assembles an agent-side translator bound to the shim and
// a fake v2c agent on 127.0.0.1:port.
func buildTranslator(t *testing.T, port int) (*shim, func()) {
	t.Helper()

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.AgentRole{
		AgentAddr:    net.JoinHostPort("127.0.0.1", itoa(port)),
		TrapSinkAddr: "",
	}
	users := []usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}

	sh := newShim()
	tr, err := usm.NewAgentTranslator(cfg, users, clock, sh, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = tr.Run(done) }()

	// fake v2c agent: responds to GET with a sysDescr-ish varbind
	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		close(done)
		t.Fatal(err)
	}
	go fakeAgent(fake)

	return sh, func() { close(done); fake.Close() }
}

// fakeAgent answers v2c GET requests with an echo varbind.
func fakeAgent(conn net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
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
		// echo the request varbinds back as a GET response (a fake agent
		// doesn't need real values — gosnmp just decodes them)
		resp := msg.BuildPDU(msg.PDUGetResponse, info.RequestID, 0, 0, fields.Varbinds)
		out, err := msg.BuildV1V2c(msg.Version2c, []byte("realcomm"), resp)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(out, addr)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) uint16 {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return uint16(n)
}

// gosnmpV3Client builds an authPriv (SHA/AES) gosnmp client.
func gosnmpV3Client(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	g := &gosnmp.GoSNMP{
		Target:        hostOf(addr),
		Port:          portOf(addr),
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

// TestInteropDiscoveryAndGet runs the full stack: gosnmp performs engine
// discovery (our Report), then issues an authPriv GET which the translator
// converts to v2c toward the fake agent; the response is converted back to
// a signed+encrypted v3 response that gosnmp verifies byte-for-byte.
func TestInteropDiscoveryAndGet(t *testing.T) {
	sh, stop := buildTranslator(t, 11611)
	defer stop()

	// UDP shim endpoint gosnmp dials (the "tunnel" side)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go bridge(sh, conn)

	g := gosnmpV3Client(t, conn.LocalAddr().String())
	defer g.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := g.Get(oids)
	if err != nil {
		t.Fatalf("v3 GET through translator: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("expected 1 varbind, got %d", len(result.Variables))
	}
	if result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("wrong OID echoed: %s", result.Variables[0].Name)
	}
}

// TestInteropWrongUser checks that an authPriv request with an unknown user
// gets our Report (usmStatsUnknownUserNames) rather than a response.
func TestInteropWrongUser(t *testing.T) {
	sh, stop := buildTranslator(t, 11612)
	defer stop()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go bridge(sh, conn)

	g := gosnmpV3Client(t, conn.LocalAddr().String())
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
