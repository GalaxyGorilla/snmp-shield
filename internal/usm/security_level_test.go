// security_level_test.go: pins the USM security-level policy of the
// request and notification paths.
//
// Two defects motivated these tests (both found by an adversarial audit):
//
//  1. No minimum security level was enforced: a message could request
//     LESS security than the user is configured for. Anyone who learns
//     the engine ID from an unauthenticated discovery Report (every USM
//     engine answers those by design) could send a NoAuthNoPriv request
//     naming an authPriv user and have it relayed to the device.
//  2. The plaintext scopedPDU path split the scopedPDU twice (ParseV3
//     already splits it), so authNoPriv / noAuthNoPriv traffic was always
//     rejected with usmStatsUnsupportedSecLevels — which is what masked
//     defect 1 and made the documented priv_protocol: none shape
//     unusable.
package usm

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// usmStatsUnsupportedSecLevels encoded as a BER OID (1.3.6.1.6.3.15.1.1.1.0).
var oidUnsupportedSecLevels = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x01, 0x00}

// usmStatsNotInTimeWindows (…15.1.1.2.0) — the counter a *timeliness*
// rejection would carry; asserting its absence keeps the test honest.
var oidNotInTimeWindows = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x02, 0x00}

// startGatewayWithUser builds and starts a gateway with one user profile
// plus a fake legacy agent. The fake agent records every datagram and,
// when reply is true, answers it with a v2c GetResponse echoing the
// request id — which exercises the gateway's response path too.
func startGatewayWithUser(t *testing.T, front, agent int, p Profile, reply bool) (*cache.EngineClock, <-chan []byte, func()) {
	t.Helper()

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	got := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, rerr := fake.ReadFrom(buf)
			if rerr != nil {
				return
			}
			dg := append([]byte(nil), buf[:n]...)
			select {
			case got <- dg:
			default:
			}
			if !reply {
				continue
			}
			info, perr := msg.Peek(dg)
			if perr != nil {
				continue
			}
			resp := msg.BuildPDU(msg.PDUGetResponse, info.RequestID, 0, 0, nil)
			out, berr := msg.BuildV1V2c(msg.Version2c, []byte("realcomm"), resp)
			if berr != nil {
				continue
			}
			_, _ = fake.WriteTo(out, addr)
		}
	}()

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gatewayCfgForTest(front, agent)
	tr, err := NewGatewayTranslator(cfg, []Profile{p}, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return clock, got, startGatewayForTest(t, tr, cfg.ListenAddr)
}

// lazyNoAuthGET builds a NoAuthNoPriv v3 GET without any gosnmp help: the
// exact shape an attacker can produce with a BER library and the engine
// ID from a discovery Report.
func lazyNoAuthGET(t *testing.T, engineID []byte, boots, etime uint32, user string, reqID int32) []byte {
	t.Helper()
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0, nil)
	scoped := msg.BuildScoped(engineID, nil, pdu)
	dg, err := msg.BuildV3(msg.V3Header{
		MsgID:      reqID,
		MsgMaxSize: 65535,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID: engineID,
		Boots:    boots,
		Time:     etime,
		UserName: user,
	}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	return dg
}

// TestGatewayRejectsSecurityLevelDowngrade: a NoAuthNoPriv request naming
// an authPriv user must be refused with usmStatsUnsupportedSecLevels and
// must never reach the legacy agent.
func TestGatewayRejectsSecurityLevelDowngrade(t *testing.T) {
	const front, agent = 12716, 12816

	clock, got, stop := startGatewayWithUser(t, front, agent, Profile{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}, false)
	defer stop()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	if err != nil {
		t.Fatal(err)
	}

	dg := lazyNoAuthGET(t, clock.EngineID(), clock.Boots(), clock.Time(), "proxy", 4242)
	if _, err := probe.WriteTo(dg, dst); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-got:
		t.Fatalf("security level downgrade reached the legacy agent: %x", raw)
	case <-time.After(1500 * time.Millisecond):
		// not forwarded: the security gate held
	}

	_ = probe.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := probe.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected a Report rejecting the downgrade: %v", err)
	}
	raw := append([]byte(nil), buf[:n]...)
	rep, err := msg.ParseV3(raw)
	if err != nil {
		t.Fatalf("parse Report: %v", err)
	}
	if len(rep.PDU) == 0 || rep.PDU[0] != msg.PDUReport {
		t.Fatalf("expected a Report PDU, got %#x", rep.PDU)
	}
	if !bytes.Contains(raw, oidUnsupportedSecLevels) {
		t.Fatalf("expected usmStatsUnsupportedSecLevels in the Report: %x", raw)
	}
	if bytes.Contains(raw, oidNotInTimeWindows) {
		t.Fatalf("downgrade was rejected by the timeliness check, not the security level check: %x", raw)
	}
}

// TestGatewayAuthNoPrivUserWorks: the documented authNoPriv shape
// (auth_protocol: sha, priv_protocol: none) must be servable end-to-end —
// request relayed as clear v2c, response rebuilt as authNoPriv v3.
func TestGatewayAuthNoPrivUserWorks(t *testing.T) {
	const front, agent = 12916, 13016

	clock, got, stop := startGatewayWithUser(t, front, agent, Profile{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivNone,
		Community:      "realcomm",
	}, true)
	defer stop()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(front)))
	if err != nil {
		t.Fatal(err)
	}

	// authNoPriv GET with a valid SHA digest, built by an independent
	// implementation (gosnmp) so the wire form is not self-referential
	eid := clock.EngineID()
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 "proxy",
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: "authpass",
		AuthoritativeEngineID:    string(eid),
		AuthoritativeEngineBoots: clock.Boots(),
		AuthoritativeEngineTime:  clock.Time(),
	}
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           gosnmp.AuthNoPriv | gosnmp.Reportable,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		PDUType:            gosnmp.GetRequest,
		MsgID:              777,
		RequestID:          777,
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
	if _, err := probe.WriteTo(raw, dst); err != nil {
		t.Fatal(err)
	}

	select {
	case forwarded := <-got:
		info, perr := msg.Peek(forwarded)
		if perr != nil || !msg.IsGet(info.PDUType) {
			t.Fatalf("forwarded datagram is not a GET: %x", forwarded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authNoPriv request was not forwarded to the agent")
	}

	// response path: authNoPriv (auth bit set, priv bit clear), GetResponse
	_ = probe.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := probe.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no v3 response for the authNoPriv request: %v", err)
	}
	resp, err := msg.ParseV3(append([]byte(nil), buf[:n]...))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Header.MsgFlags&msg.MsgFlagAuth == 0 {
		t.Errorf("response is unsigned; want the auth bit set")
	}
	if resp.Header.MsgFlags&msg.MsgFlagPriv != 0 {
		t.Errorf("response claims privacy for a priv-less user")
	}
	if len(resp.PDU) == 0 || resp.PDU[0] != msg.PDUGetResponse {
		t.Fatalf("expected a plaintext GetResponse, got %#x", resp.PDU)
	}
}

// TestEnforceSecurityLevel is the table-level pin for the policy matrix.
func TestEnforceSecurityLevel(t *testing.T) {
	authPriv := &compiled{p: Profile{AuthProtocol: AuthSHA, PrivProtocol: PrivAES}}
	authNoPriv := &compiled{p: Profile{AuthProtocol: AuthSHA, PrivProtocol: PrivNone}}
	noAuth := &compiled{p: Profile{AuthProtocol: AuthNone, PrivProtocol: PrivNone}}

	cases := []struct {
		name   string
		c      *compiled
		flags  byte
		wantOK bool
	}{
		{"authPriv user, authPriv msg", authPriv, msg.MsgFlagAuth | msg.MsgFlagPriv, true},
		{"authPriv user, authNoPriv msg", authPriv, msg.MsgFlagAuth, false},
		{"authPriv user, noAuth msg", authPriv, msg.MsgFlagReportable, false},
		{"authPriv user, priv w/o auth", authPriv, msg.MsgFlagPriv, false},
		{"authNoPriv user, authNoPriv msg", authNoPriv, msg.MsgFlagAuth, true},
		{"authNoPriv user, authPriv msg", authNoPriv, msg.MsgFlagAuth | msg.MsgFlagPriv, false},
		{"authNoPriv user, noAuth msg", authNoPriv, msg.MsgFlagReportable, false},
		{"noAuth user, noAuth msg", noAuth, msg.MsgFlagReportable, true},
		{"noAuth user, auth msg", noAuth, msg.MsgFlagAuth, false},
	}
	for _, tc := range cases {
		err := enforceSecurityLevel(tc.c, tc.flags)
		if tc.wantOK && err != nil {
			t.Errorf("%s: want accepted, got %v", tc.name, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("%s: want rejected, got accepted", tc.name)
		}
	}
}
