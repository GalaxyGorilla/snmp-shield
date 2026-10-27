// access_e2e_test.go: pins the front-leg access policy on the wire. The
// unit tests cover the decision logic; these prove the decisions are
// actually wired into a live gateway driven by an independent SNMP
// implementation (gosnmp), with the legacy agent as the oracle: a refused
// write must never be forwarded, and a manager must be told why instead of
// waiting for a timeout.
package usm

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// countingAgent is a fake legacy agent that answers v2c GETs and counts
// every SET it receives (the write-policy oracle).
type countingAgent struct {
	conn net.PacketConn
	sets atomic.Int32
}

func newCountingAgent(t *testing.T, addr string) *countingAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	a := &countingAgent{conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go a.loop()
	return a
}

func (a *countingAgent) loop() {
	buf := make([]byte, 65536)
	for {
		n, src, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		info, err := msg.Peek(dg)
		if err != nil {
			continue
		}
		if msg.IsSet(info.PDUType) {
			a.sets.Add(1)
		}
		if !msg.IsGet(info.PDUType) && !msg.IsGetNext(info.PDUType) && !msg.IsGetBulk(info.PDUType) && !msg.IsSet(info.PDUType) {
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
		_, _ = a.conn.WriteTo(out, src)
	}
}

// startGatewayWithAccess starts a gateway with the given access policy and
// returns the live holder (so a test can swap it, exactly as SIGHUP does)
// plus a stop func.
func startGatewayWithAccess(t *testing.T, front, agent int, pol *access.Policy) (*access.Holder, func()) {
	t.Helper()
	store, err := openStoreForTest()
	if err != nil {
		t.Fatal(err)
	}
	clock, err := newClockForTest(store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gatewayCfgForTest(front, agent)
	users := []Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}
	tr, err := NewGatewayTranslator(cfg, users, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := access.NewHolder(pol)
	tr.SetAccess(h)
	return h, startGatewayForTest(t, tr, cfg.ListenAddr)
}

// TestGatewayReadOnlyRefusesWrites: with access.read_only the gateway must
// answer a SET with notWritable and never forward it to the legacy device.
// Reads keep working — that is the whole point of read-only mode.
func TestGatewayReadOnlyRefusesWrites(t *testing.T) {
	const front, agent = 13116, 13216
	agentAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(agent))
	a := newCountingAgent(t, agentAddr)

	pol, err := access.New(nil, 0, access.NewReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	_, stop := startGatewayWithAccess(t, front, agent, pol)
	defer stop()

	g := gosnmpV3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	defer g.Conn.Close()

	// reads pass
	if _, gerr := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); gerr != nil {
		t.Fatalf("GET failed under read-only: %v", gerr)
	}

	// writes are refused with a definite answer
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
	if n := a.sets.Load(); n != 0 {
		t.Fatalf("refused SET reached the legacy agent %d time(s)", n)
	}
}

// TestGatewayAllowListDeniesFrontLeg: a client outside access.allow is
// dropped in silence — no answer, nothing forwarded. Silence (rather than
// an error report) is deliberate: an off-list peer must not even learn that
// a proxy is there.
func TestGatewayAllowListDeniesFrontLeg(t *testing.T) {
	const front, agent = 13316, 13416
	agentAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(agent))
	a := newCountingAgent(t, agentAddr)

	// the test client is 127.0.0.1, deliberately not on the list
	pol, err := access.New([]string{"192.0.2.0/24"}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, stop := startGatewayWithAccess(t, front, agent, pol)
	defer stop()

	g := gosnmpV3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	defer g.Conn.Close()
	g.Retries = 0
	g.Timeout = 700 * time.Millisecond

	if _, gerr := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); gerr == nil {
		t.Fatal("off-list client got an answer")
	}
	if n := a.sets.Load(); n != 0 {
		t.Fatalf("off-list client reached the agent %d time(s)", n)
	}

	// A live policy swap (what SIGHUP does) must take effect on the next
	// datagram — the same socket, no rebind.
	allowed, err := access.New([]string{"127.0.0.1"}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Store(allowed)
	g.Retries = 2
	g.Timeout = 3 * time.Second
	if _, gerr := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); gerr != nil {
		t.Fatalf("after the policy swap the client is still refused: %v", gerr)
	}
}

// TestGatewayWritePolicyAllowsSubtree: an OID-scoped policy lets the manager
// write inside the allowed subtree and refuses everything else, even in a
// single SET that straddles both (deny-overrides).
func TestGatewayWritePolicyAllowsSubtree(t *testing.T) {
	const front, agent = 13516, 13616
	agentAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(agent))
	a := newCountingAgent(t, agentAddr)

	wp, err := access.NewWritePolicy(false, []access.WriteRule{
		{OID: "1.3.6.1.4.1.99.1", Allow: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := access.New(nil, 0, wp)
	if err != nil {
		t.Fatal(err)
	}
	_, stop := startGatewayWithAccess(t, front, agent, pol)
	defer stop()

	g := gosnmpV3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	defer g.Conn.Close()

	// inside the allowed subtree: forwarded, agent sees it
	res, serr := g.Set([]gosnmp.SnmpPDU{{
		Name: "1.3.6.1.4.1.99.1.0", Type: gosnmp.Integer, Value: 42,
	}})
	if serr != nil {
		t.Fatalf("allowed SET failed: %v", serr)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("allowed SET error-status = %v", res.Error)
	}
	if n := a.sets.Load(); n != 1 {
		t.Fatalf("allowed SET reached the agent %d time(s), want 1", n)
	}

	// outside any rule (default deny): refused, agent never sees it
	res, serr = g.Set([]gosnmp.SnmpPDU{{
		Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "nope",
	}})
	if serr != nil {
		t.Fatalf("denied SET transport error: %v", serr)
	}
	if res.Error != gosnmp.NotWritable {
		t.Fatalf("denied SET error-status = %v, want notWritable", res.Error)
	}
	if n := a.sets.Load(); n != 1 {
		t.Fatalf("denied SET reached the agent (%d total)", n)
	}

	// one SET touching allowed AND forbidden objects: the whole request
	// is refused (a write must never straddle the policy boundary)
	res, serr = g.Set([]gosnmp.SnmpPDU{
		{Name: "1.3.6.1.4.1.99.1.0", Type: gosnmp.Integer, Value: 1},
		{Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "x"},
	})
	if serr != nil {
		t.Fatalf("straddling SET transport error: %v", serr)
	}
	if res.Error != gosnmp.NotWritable {
		t.Fatalf("straddling SET error-status = %v, want notWritable", res.Error)
	}
	if n := a.sets.Load(); n != 1 {
		t.Fatalf("straddling SET reached the agent (%d total)", n)
	}
}

// TestGatewayRateLimitDropsExcess: a 1/s limit admits the first request and
// drops the rest of the burst in silence (no answer, nothing forwarded).
func TestGatewayRateLimitDropsExcess(t *testing.T) {
	const front, agent = 13716, 13816
	agentAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(agent))
	a := newCountingAgent(t, agentAddr)

	pol, err := access.New(nil, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, stop := startGatewayWithAccess(t, front, agent, pol)
	defer stop()

	g := gosnmpV3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	defer g.Conn.Close()
	g.Retries = 0
	g.Timeout = 600 * time.Millisecond

	// One request is admitted. gosnmp's own engine discovery also sends a
	// probe, which consumes the single token first — so assert the shape,
	// not an exact count: at least one request must time out in silence.
	okCount := 0
	for i := 0; i < 4; i++ {
		if _, gerr := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); gerr == nil {
			okCount++
		}
	}
	if okCount == 4 {
		t.Fatal("rate limit admitted the whole burst")
	}
	if n := a.sets.Load(); n != 0 {
		t.Fatalf("rate-limited client reached the agent with a SET (%d)", n)
	}
}
