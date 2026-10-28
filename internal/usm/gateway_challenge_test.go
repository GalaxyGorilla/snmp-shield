// gateway_challenge_test.go (package usm): adversarial/edge-case tests
// for the single-box USM gateway beyond the happy paths. These challenge
// the security gate directly on the wire: stale engine time, tampered
// digests, GetBulk relaying, garbage datagrams, and non-reportable
// silent drops.
package usm

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// challengeGateway is the white-box harness: like buildGateway in
// package usm_test but inside the package so tests can inspect pend and
// counters.
func challengeGateway(t *testing.T, front, agent int) (*GatewayTranslator, func()) {
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
	return tr, startGatewayForTest(t, tr, cfg.ListenAddr)
}

// startGatewayForTest starts a gateway and makes both startup and shutdown
// failures visible to the test. Run owns its sockets, so returning before it
// has bound (or after done is closed but before it has exited) makes
// subsequent tests flaky, especially under the race detector.
func startGatewayForTest(t *testing.T, tr *GatewayTranslator, addr string) func() {
	t.Helper()
	done := make(chan struct{})
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- tr.Run(done, ready)
		close(runErr)
	}()
	waitGatewayReady(t, addr, ready, runErr)

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

// TestGatewayStaleEngineTimeRejected: an authenticated request claiming
// an out-of-window engineTime (same boots) must be rejected with a
// usmStatsNotInTimeWindows Report and never forwarded.
func TestGatewayStaleEngineTimeRejected(t *testing.T) {
	const front, agent = 12616, 11716
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	gotForward := make(chan int, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case gotForward <- n:
			default:
			}
		}
	}()

	tr, stop := challengeGateway(t, front, agent)
	defer stop()

	// The gateway clock is fresh (boots=1, engineTime ~0). A failover
	// manager sends its OLD higher boots with a valid digest — per RFC
	// 3414 that is a logical reboot and the HA state-sync rule adopts it
	// (verified traffic only). The stale claim here is therefore a
	// same-boots out-of-window engineTime (now+3600), which stays
	// rejected by the timeliness window.
	raw := craftV3GET(t, tr.clock.EngineID(), tr.clock.Boots(), tr.clock.Time()+3600, 42)
	addr, err := net.ResolveUDPAddr("udp", frontAddr)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(raw, addr); err != nil {
		t.Fatal(err)
	}

	// The gateway must answer with a Report (0xA8) whose varbind carries
	// usmStatsNotInTimeWindows (1.3.6.1.6.3.15.1.1.2.0).
	rep := readReport(t, probe)
	if got := reportStatSuffix(t, rep); got != 2 {
		t.Fatalf("expected usmStatsNotInTimeWindows (suffix 2), got suffix %d", got)
	}

	// Nothing may reach the legacy agent.
	select {
	case n := <-gotForward:
		t.Fatalf("stale-time request was forwarded to the legacy agent (%d bytes)", n)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestGatewayTamperedDigestRejected: flipping one byte inside the
// authenticated PDU must fail digest verification — usmStatsWrongDigests
// Report, never forwarded.
func TestGatewayTamperedDigestRejected(t *testing.T) {
	const front, agent = 12617, 11717
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	gotForward := make(chan int, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case gotForward <- n:
			default:
			}
		}
	}()

	tr, stop := challengeGateway(t, front, agent)
	defer stop()

	raw := craftV3GET(t, tr.clock.EngineID(), tr.clock.Boots(), tr.clock.Time(), 43)

	// Tamper: flip a byte near the end (inside the encrypted scopedPDU).
	// The digest then no longer matches.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 0xff

	addr, _ := net.ResolveUDPAddr("udp", frontAddr)
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(tampered, addr); err != nil {
		t.Fatal(err)
	}

	rep := readReport(t, probe)
	if got := reportStatSuffix(t, rep); got != 5 {
		t.Fatalf("expected usmStatsWrongDigests (suffix 5), got suffix %d", got)
	}

	select {
	case n := <-gotForward:
		t.Fatalf("tampered request was forwarded to the legacy agent (%d bytes)", n)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestGatewayNonReportableSilentDrop: the same stale-time attack WITHOUT
// the Reportable flag must be dropped in complete silence (no Report,
// no forwarding) — a manager that did not ask for a report gets nothing.
func TestGatewayNonReportableSilentDrop(t *testing.T) {
	const front, agent = 12618, 11718
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	gotForward := make(chan int, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case gotForward <- n:
			default:
			}
		}
	}()

	tr, stop := challengeGateway(t, front, agent)
	defer stop()

	// The stale-time attack WITHOUT the Reportable flag: same-boots
	// out-of-window engineTime (now+3600) — rejected in complete
	// silence (no Report, no forwarding). (A higher-boots attack would
	// be pointless anyway: without the Reportable flag it is also
	// dropped, and with a valid digest it would be a legitimate HA
	// failover that the state-sync rule adopts.)
	raw := craftV3GETFlags(t, tr.clock.EngineID(), tr.clock.Boots(), tr.clock.Time()+3600, 44,
		gosnmp.AuthPriv) // no Reportable flag

	addr, _ := net.ResolveUDPAddr("udp", frontAddr)
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(raw, addr); err != nil {
		t.Fatal(err)
	}

	if err := probe.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	if n, _, err := probe.ReadFrom(buf); err == nil {
		t.Fatalf("non-reportable attack elicited a reply (%d bytes), want silence", n)
	}
	select {
	case n := <-gotForward:
		t.Fatalf("non-reportable attack was forwarded (%d bytes)", n)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestGatewayGetBulkRelay: an authPriv GetBulk must traverse the gateway
// and be relayed as GetBulk (v2c downstream) — the fake agent's echo
// reply must come back as a proper v3 response.
func TestGatewayGetBulkRelay(t *testing.T) {
	const front, agent = 12619, 11719
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	_, stop := challengeGateway(t, front, agent)
	defer stop()

	g := gosnmpV3Client(t, frontAddr)
	defer g.Conn.Close()
	result, err := g.GetBulk([]string{"1.3.6.1.2.1.1"}, 0, 3)
	if err != nil {
		t.Fatalf("v3 GetBulk through gateway: %v", err)
	}
	if len(result.Variables) == 0 {
		t.Fatal("GetBulk returned no varbinds")
	}
	// The echo agent returns the requested OID (proving the GetBulk PDU
	// — type 0xA5 with non-repeaters/max-repetitions — traversed the
	// gateway intact rather than being rewritten or dropped).
	if result.Variables[0].Name != ".1.3.6.1.2.1.1" {
		t.Fatalf("wrong OID echoed: %s", result.Variables[0].Name)
	}
}

// TestGatewayGarbageDoesNotKillFront: hostile datagrams (random noise,
// truncated v3 headers, oversized claims) must be dropped without
// panicking or stopping the front listener — an authenticated request
// afterwards still works.
func TestGatewayGarbageDoesNotKillFront(t *testing.T) {
	const front, agent = 12620, 11720
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	_, stop := challengeGateway(t, front, agent)
	defer stop()

	addr, _ := net.ResolveUDPAddr("udp", frontAddr)
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()

	garbage := [][]byte{
		{},                                   // empty
		{0x30, 0x82, 0xff, 0xff, 0x00, 0x00}, // huge declared length, truncated
		[]byte("\x30\x03\x04\x01\x01"),       // SEQUENCE with garbage body
		[]byte("\xff\xff\xff\xff\xff\xff"),   // not BER at all
		bytes.Repeat([]byte{0x42}, 64),       // constant noise
	}
	for _, g := range garbage {
		if _, err := probe.WriteTo(g, addr); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)

	// The listener must still serve authenticated traffic.
	g := gosnmpV3Client(t, frontAddr)
	defer g.Conn.Close()
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("front listener dead after garbage: %v", err)
	}
}

// TestGatewayResponseIsUnconfirmedClass: a v3 Response must echo the
// manager's msgID and must NOT carry the Reportable flag — only
// confirmed-class messages (requests, informs) set it (RFC 3412 §6.4).
//
// We used to echo the request's flags verbatim, Reportable included. Every
// vendor we test tolerates that, so no interop suite failed; the wire was
// still malformed. Both halves are checked here on the raw datagram.
func TestGatewayResponseIsUnconfirmedClass(t *testing.T) {
	const front, agent = 12622, 11722
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	tr, stop := challengeGateway(t, front, agent)
	defer stop()

	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	dst, err := net.ResolveUDPAddr("udp", frontAddr)
	if err != nil {
		t.Fatal(err)
	}
	// craftV3GET sends msgID 1234 and AuthPriv|Reportable, exactly like a
	// manager's first authenticated request after discovery.
	req := craftV3GET(t, tr.clock.EngineID(), tr.clock.Boots(), tr.clock.Time(), 77)
	if _, err := src.WriteTo(req, dst); err != nil {
		t.Fatal(err)
	}

	if err := src.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, _, err := src.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response to a valid authPriv GET: %v", err)
	}
	m, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("response is not v3: %v", err)
	}
	if m.Header.MsgFlags&msg.MsgFlagReportable != 0 {
		t.Fatalf("response flags = %#x: the Reportable flag is set on an unconfirmed-class PDU", m.Header.MsgFlags)
	}
	if m.Header.MsgFlags&(msg.MsgFlagAuth|msg.MsgFlagPriv) != msg.MsgFlagAuth|msg.MsgFlagPriv {
		t.Fatalf("response flags = %#x, want authPriv preserved", m.Header.MsgFlags)
	}
	if m.Header.MsgID != 1234 {
		t.Fatalf("response msgID = %d, want the request's 1234", m.Header.MsgID)
	}
}

// --- helpers ----------------------------------------------------------------

// openStoreForTest opens an in-memory engine store (challenge helper).
func openStoreForTest() (*cache.Store, error) {
	return cache.Open("")
}

// newClockForTest builds an engine clock over the store.
func newClockForTest(store *cache.Store) (*cache.EngineClock, error) {
	return cache.NewEngineClock(store, nil, nil)
}

// gatewayCfgForTest builds gateway config for loopback ports.
func gatewayCfgForTest(front, agent int) config.GatewayRole {
	return config.GatewayRole{
		ListenAddr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(front)),
		AgentAddr:      net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)),
		AgentCommunity: "realcomm",
	}
}

// waitGatewayReady waits for an explicit readiness signal, while surfacing an
// early gateway startup failure. Binding a probe socket to test readiness
// races with the gateway's own bind on Darwin.
func waitGatewayReady(t *testing.T, addr string, ready <-chan struct{}, runErr <-chan error) {
	t.Helper()
	select {
	case <-ready:
		return
	case err, ok := <-runErr:
		if !ok {
			t.Fatalf("gateway at %s exited during startup without an error", addr)
		}
		t.Fatalf("gateway at %s exited during startup: %v", addr, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for gateway at %s to start", addr)
	}
}

// craftV3GET builds a signed+encrypted v3 GET as a real manager would,
// with full control over the USM boots/time (challenge helper).
func craftV3GET(t *testing.T, eid []byte, boots, tm uint32, reqID int32) []byte {
	t.Helper()
	return craftV3GETFlags(t, eid, boots, tm, reqID, gosnmp.AuthPriv|gosnmp.Reportable)
}

func craftV3GETFlags(t *testing.T, eid []byte, boots, tm uint32, reqID int32, flags gosnmp.SnmpV3MsgFlags) []byte {
	t.Helper()
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 "proxy",
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: "authpass",
		PrivacyProtocol:          gosnmp.AES,
		PrivacyPassphrase:        "privpass",
		AuthoritativeEngineID:    string(eid),
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  tm,
	}
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           flags,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		PDUType:            gosnmp.GetRequest,
		MsgID:              1234,
		RequestID:          uint32(reqID),
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null, Value: nil},
		},
	}
	if err := sp.InitSecurityKeys(); err != nil {
		t.Fatal(err)
	}
	if err := sp.InitPacket(pkt); err != nil {
		t.Fatal(err)
	}
	raw, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// readReport reads one datagram and asserts it is a Report PDU (the
// PDU type is read from the parsed v3 message — Peek cannot see inside
// an encrypted scopedPDU).
func readReport(t *testing.T, probe net.PacketConn) []byte {
	t.Helper()
	if err := probe.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, _, err := probe.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected a Report reply: %v", err)
	}
	dg := append([]byte(nil), buf[:n]...)
	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("Report reply undecodable: %v", err)
	}
	if len(m.PDU) == 0 || m.PDU[0] != msg.PDUReport {
		t.Fatalf("expected Report PDU (0xA8), got 0x%02x", m.PDU[0])
	}
	return dg
}

// reportStatSuffix extracts the usmStats counter suffix from a Report's
// varbind OID (1.3.6.1.6.3.15.1.1.<x>.0).
func reportStatSuffix(t *testing.T, dg []byte) uint64 {
	t.Helper()
	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("report undecodable: %v", err)
	}
	_, fields, err := msg.ParsePDU(m.PDU)
	if err != nil {
		t.Fatalf("report PDU undecodable: %v", err)
	}
	if len(fields.Varbinds) == 0 || fields.Varbinds[0] != 0x30 {
		t.Fatal("report carries no varbind SEQUENCE")
	}
	vb := fields.Varbinds
	vbLen, body, err := berLenOf(vb[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < vbLen {
		t.Fatal("truncated varbind")
	}
	oidTLV := body
	if len(oidTLV) < 2 || oidTLV[0] != 0x06 {
		t.Fatal("report varbind OID TLV missing")
	}
	oidLen, oidBody, err := berLenOf(oidTLV[1:])
	if err != nil {
		t.Fatal(err)
	}
	dotted, err := msg.DecodeOID(oidBody[:oidLen])
	if err != nil {
		t.Fatal(err)
	}
	// suffix is the second-to-last arc (last is .0)
	var arcs []uint64
	cur := uint64(0)
	for i := 0; i < len(dotted); i++ {
		if dotted[i] == '.' {
			arcs = append(arcs, cur)
			cur = 0
			continue
		}
		cur = cur*10 + uint64(dotted[i]-'0')
	}
	arcs = append(arcs, cur)
	if len(arcs) < 2 {
		t.Fatalf("unexpected usmStats OID %q", dotted)
	}
	return arcs[len(arcs)-2]
}

// errChallengeBER marks a malformed BER length in challenge test helpers.
var errChallengeBER = errors.New("challenge: malformed BER length")

// berLenOf parses one BER length field (challenge helper).
func berLenOf(buf []byte) (int, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, errChallengeBER
	}
	if buf[0] < 0x80 {
		return int(buf[0]), buf[1:], nil
	}
	n := int(buf[0] & 0x7f)
	if n == 0 || n > 4 || len(buf) < 1+n {
		return 0, nil, errChallengeBER
	}
	l := 0
	for _, b := range buf[1 : 1+n] {
		l = l<<8 | int(b)
	}
	return l, buf[1+n:], nil
}

// gosnmpV3Client builds a v3 authPriv client against the gateway front
// (challenge helper; mirrors the usm_test helper).
func gosnmpV3Client(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	g := &gosnmp.GoSNMP{
		Target:        host,
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
		t.Fatal(err)
	}
	return g
}

// fakeAgent is a fake legacy agent echoing GET/GETNEXT/GETBULK varbinds
// as v2c (challenge helper; mirrors the usm_test fake agent).
func fakeAgent(conn net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		info, err := msg.Peek(dg)
		if err != nil {
			continue
		}
		if !msg.IsGet(info.PDUType) && !msg.IsGetNext(info.PDUType) && !msg.IsGetBulk(info.PDUType) {
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
		_, _ = conn.WriteTo(out, addr)
	}
}
