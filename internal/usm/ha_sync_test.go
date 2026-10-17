// ha_sync_test.go (package usm): wire-level tests for the HA pair state
// sync. When two agent-side proxies (or gateway replicas) share an
// engineID but keep separate engine stores, the replica that takes over
// has a LOWER persisted boots than the formerly-active peer. These tests
// pin the convergence rule: a digest-verified higher-boots claim is
// adopted as a logical reboot (RFC 3414) and serves, unverified claims
// never adopt, and the manager's discovery cache follows the wire.
package usm

import (
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

// TestHAFailoverAdoptsHigherBoots: a replica with a shared engineID but a
// lower persisted boots takes over; the manager's first request claims
// the OLD (higher) boots with a valid digest. The gateway must adopt it
// (logical reboot) and serve the request instead of rejecting forever.
func TestHAFailoverAdoptsHigherBoots(t *testing.T) {
	const front, agent = 12621, 11721
	frontAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(front))

	fake, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agent)))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go fakeAgent(fake)

	// The standby replica: fresh engine clock (boots=1) with the shared
	// engineID the pair agreed on.
	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, []byte{0x80, 0xAA, 0x55}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewGatewayTranslator(gatewayCfgForTest(front, agent), []Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = tr.Run(done) }()
	defer close(done)
	waitBoundForChallenge(t, frontAddr)

	// The manager's cached state: the formerly-active peer was at
	// boots=5 (engineTime well past our fresh window).
	const oldBoots, oldTime = 5, 200
	if err := clock.AcceptInbound(oldBoots, oldTime); err == nil {
		t.Fatal("pre-adopt state must be rejected (standby boots is lower)")
	}

	// First request after the failover: valid digest, OLD higher boots.
	g := gosnmpV3ClientFor(t, frontAddr, oldBoots, oldTime)
	defer g.Conn.Close()
	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("first request after HA failover must be served (boots adoption), got: %v", err)
	}
	if len(result.Variables) == 0 {
		t.Fatal("no varbinds in failover response")
	}

	// The engine clock now reflects the adopted boots...
	if got := clock.Boots(); got != oldBoots {
		t.Fatalf("clock should adopt the old boots (%d), got %d", oldBoots, got)
	}
	// ...and subsequent requests on the SAME (old) timeline must work —
	// gosnmp caches the engine state, so this replays the same pair.
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("second request on the adopted timeline failed: %v", err)
	}
}

// TestHAUnverifiedBootsNeverAdopts: the same stale-boots claim WITHOUT
// authentication (no digest to verify) must NOT adopt and must be
// rejected — the protection gate stays closed for unverified traffic.
func TestHAUnverifiedBootsNeverAdopts(t *testing.T) {
	const front, agent = 12622, 11722
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

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, []byte{0x80, 0xAA, 0x56}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewGatewayTranslator(gatewayCfgForTest(front, agent), []Profile{{
		Name:         "proxy",
		AuthProtocol: AuthNone, // gateway serves NoAuth users; no digest
		PrivProtocol: PrivNone,
		Community:    "realcomm",
	}}, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = tr.Run(done) }()
	defer close(done)
	waitBoundForChallenge(t, frontAddr)

	// NoAuthNoPriv reportable request claiming a HIGHER boots: the
	// digest-verified gate must keep it out (rejected, nothing adopted).
	raw := craftV3GETFlags(t, clock.EngineID(), clock.Boots()+9, 1, 45,
		gosnmp.NoAuthNoPriv|gosnmp.Reportable)
	addr, _ := net.ResolveUDPAddr("udp", frontAddr)
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.WriteTo(raw, addr); err != nil {
		t.Fatal(err)
	}

	// usmStatsNotInTimeWindows Report (suffix 2), and nothing forwarded.
	rep := readReport(t, probe)
	if got := reportStatSuffix(t, rep); got != 2 {
		t.Fatalf("expected usmStatsNotInTimeWindows (suffix 2), got suffix %d", got)
	}
	select {
	case n := <-gotForward:
		t.Fatalf("unverified boots claim was forwarded (%d bytes)", n)
	case <-time.After(300 * time.Millisecond):
	}
	if got := clock.Boots(); got != 1 {
		t.Fatalf("unverified claim must not adopt, boots=%d", got)
	}
}

// TestHAReportFollowsWire: the manager-side discovery cache must adopt a
// same-engine Report whose boots/time REGRESSED (the failed-over
// replica's announcement); a stale replayed Report only re-syncs once —
// the engine-side checks are the real anti-rollback boundary.
func TestHAReportFollowsWire(t *testing.T) {
	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManagerTranslator(config.ManagerRole{}, config.Security{}, clock, &testShim{}, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.remote = &remoteEngine{id: []byte{0x01}, boots: 9, time: 999, discoveredAt: time.Now()}

	buildReport := func(engineID []byte, boots, tm uint32) *msg.V3Message {
		pdu := msg.BuildPDU(msg.PDUReport, 1, 0, 0, []byte{0})
		scoped := msg.BuildScoped(nil, []byte{}, pdu)
		out, err := msg.BuildV3(msg.V3Header{
			MsgID:      1,
			MsgMaxSize: msg.DefaultMsgMaxSize,
			MsgFlags:   msg.MsgFlagReportable,
			SecModel:   msg.SecurityModelUSM,
		}, msg.USMParams{EngineID: engineID, Boots: boots, Time: tm}, scoped, nil)
		if err != nil {
			t.Fatal(err)
		}
		m2, err := msg.ParseV3(out)
		if err != nil {
			t.Fatal(err)
		}
		return m2
	}

	// Same engineID, regressed boots/time (the failed-over replica's
	// announcement): adopted, the manager re-targets the new active.
	m.handleReport(buildReport([]byte{0x01}, 2, 5))
	m.engineMu.Lock()
	boots, tm := m.remote.boots, m.remote.time
	m.engineMu.Unlock()
	if boots != 2 || tm != 5 {
		t.Fatalf("regressed same-engine Report must be adopted, got boots=%d time=%d", boots, tm)
	}

	// A replayed STALE Report (older than what we just adopted) also
	// follows the wire — the engine rejects stale requests itself and
	// answers with a notInTime Report carrying its current state, which
	// re-syncs this cache. It must NOT wedge the manager.
	m.handleReport(buildReport([]byte{0x01}, 1, 1))
	m.engineMu.Lock()
	boots = m.remote.boots
	m.engineMu.Unlock()
	if boots != 1 {
		t.Fatalf("stale replayed Report must follow the wire, boots=%d", boots)
	}

	// An identical Report is a no-op.
	m.handleReport(buildReport([]byte{0x01}, 1, 1))
	m.engineMu.Lock()
	boots, tm = m.remote.boots, m.remote.time
	m.engineMu.Unlock()
	if boots != 1 || tm != 1 {
		t.Fatalf("identical Report must not change state, boots=%d time=%d", boots, tm)
	}
}

// gosnmpV3ClientFor builds a v3 authPriv client pinned to a specific
// (boots, time) pair — simulating a manager whose engine cache still
// holds the failed-over-from state.
func gosnmpV3ClientFor(t *testing.T, addr string, boots, tm uint32) *gosnmp.GoSNMP {
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
			AuthoritativeEngineID:    string([]byte{0x80, 0xAA, 0x55}),
			AuthoritativeEngineBoots: boots,
			AuthoritativeEngineTime:  tm,
		},
	}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	return g
}
