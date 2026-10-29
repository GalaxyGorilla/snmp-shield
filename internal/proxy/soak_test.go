// Soak tests: the properties only minutes of continuous traffic can show.
//
// They are skipped unless SNMP_SHIELD_SOAK=1 (`make soak`), because a
// ten-minute test in `go test ./...` would be a ten-minute edit loop. The two
// here target the two gaps recorded in TESTING.md: a steady-state chain that
// must stay flat (goroutines, live heap, zero unanswered requests) and HA —
// pinned elsewhere as a state machine — as an actual outage, with one replica
// killed mid-poll.
package proxy

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

const soakPollInterval = 20 * time.Millisecond

// chainPoll is a v2c client that issues GETs through the manager's clear leg
// and waits for the answer with the matching req-id. Shared by the soak tests
// and the per-request goroutine regression test.
type chainPoll struct {
	sock net.PacketConn
	dst  *net.UDPAddr
	oid  []byte
	next int32
}

func newChainPoll(t *testing.T, listen string) *chainPoll {
	t.Helper()
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	dst, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return &chainPoll{sock: sock, dst: dst, oid: oid}
}

// once performs one round trip. A stale answer (an earlier req-id that
// arrived late) is ignored rather than accepted, so a request is never
// credited with somebody else's response.
func (p *chainPoll) once(timeout time.Duration) (time.Duration, error) {
	p.next++
	reqID := p.next
	pdu := msg.BuildPDU(msg.PDUGetRequest, reqID, 0, 0,
		msg.AppendTLV(msg.AppendTLV(nil, 0x06, p.oid), 0x05, nil))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := p.sock.WriteTo(dg, p.dst); err != nil {
		return 0, err
	}
	deadline := start.Add(timeout)
	buf := make([]byte, 65536)
	for {
		if err := p.sock.SetReadDeadline(deadline); err != nil {
			return time.Since(start), err
		}
		n, _, err := p.sock.ReadFrom(buf)
		if err != nil {
			return time.Since(start), err
		}
		_, _, rpdu, err := msg.SplitV1V2c(buf[:n])
		if err != nil {
			continue
		}
		_, fields, err := msg.ParsePDU(rpdu)
		if err != nil {
			continue
		}
		if fields.ReqID == reqID {
			return time.Since(start), nil
		}
	}
}

// TestSoakSteadyState keeps one two-proxy chain busy for the budget and
// asserts it stays flat. A leak does not need a crash to hurt an appliance:
// a goroutine per request or a heap that tracks the request counter ends the
// same way, weeks later.
func TestSoakSteadyState(t *testing.T) {
	budget := testkit.SoakDuration(t)

	met := observ.NewMetrics()
	device := fakeAgent(t, "127.0.0.1:0")
	defer device.Close()

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = device.LocalAddr().String()

	agCancel, agErr := startAgent(t, agentCfg, met)
	defer agCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentCfg.Tunnel.ListenAddr}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrCfg.Manager.ListenAddr)

	poll := newChainPoll(t, mgrCfg.Manager.ListenAddr)
	for i := 0; i < 5; i++ {
		if _, err := poll.once(5 * time.Second); err != nil {
			t.Fatalf("warmup request %d: %v", i, err)
		}
	}

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)

	var (
		ok, failed, maxGoroutines int
		worst                     time.Duration
		lastErr                   error
	)
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	nextSample := time.Now().Add(sampleEvery)

	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		elapsed, err := poll.once(2 * time.Second)
		if err != nil {
			failed++
			lastErr = err
		} else {
			ok++
			if elapsed > worst {
				worst = elapsed
			}
		}
		if time.Now().After(nextSample) {
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			nextSample = time.Now().Add(sampleEvery)
		}
		time.Sleep(soakPollInterval)
	}

	if failed != 0 {
		t.Fatalf("%d of %d requests were unanswered over %s (last error: %v)", failed, ok+failed, budget, lastErr)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("soak: %s, %d requests, worst round trip %s, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, ok, worst.Round(time.Millisecond), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))

	stopRun(t, agCancel, agErr, "agent")
	stopRun(t, mgCancel, mgErr, "manager")
	waitGoroutines(t, baseGoroutines+8, 15*time.Second)
}

// TestSoakHAFailoverUnderLoad kills one agent-side replica while a manager is
// polling continuously and asserts the deployment recovers: the outage is
// bounded, the remaining replica keeps answering, and the tunnel comes back
// up. The HA tests elsewhere pin the state machine; this pins the experience.
func TestSoakHAFailoverUnderLoad(t *testing.T) {
	budget := testkit.SoakDuration(t)
	baseline := runtime.NumGoroutine()

	device := fakeAgent(t, "127.0.0.1:0")
	defer device.Close()

	// Two replicas: same device, same PSK, separate tunnel listeners. A
	// manager that knows both can be failed over by killing either.
	startReplica := func() (listen string, cancel func(), errCh chan error) {
		cfg := &config.Config{Role: config.RoleAgent}
		cfg.Defaults()
		cfg.Tunnel.Mode = "dtls"
		cfg.Tunnel.ListenAddr = freeUDPPort(t)
		cfg.Tunnel.PSK = "text:testpsk"
		cfg.Agent.AgentAddr = device.LocalAddr().String()
		cancel, errCh = startAgent(t, cfg, observ.NewMetrics())
		return cfg.Tunnel.ListenAddr, cancel, errCh
	}
	aListen, aCancel, aErr := startReplica()
	bListen, bCancel, bErr := startReplica()
	// Cleanup order: the manager first (deferred last), then both replicas.
	// A replica cancelled by the test is stopped explicitly; cancelling it
	// again is harmless.
	defer bCancel()
	defer aCancel()

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{aListen, bListen}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	// Failover speed is what makes this testable: 3 idle misses × 3×1s
	// before the dead peer is declared, then a redial that walks the list.
	mgrCfg.Tunnel.KeepaliveSecs = 1
	mgrCfg.Tunnel.MaxReconnectBackoff = 1
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	met := observ.NewMetrics()

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	defer mgCancel()
	waitBound(t, mgrCfg.Manager.ListenAddr)

	poll := newChainPoll(t, mgrCfg.Manager.ListenAddr)
	if _, err := poll.once(5 * time.Second); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	killAt := time.Now().Add(budget / 3)
	var (
		successesBefore, failuresBefore int
		successesAfter, failuresAfter   int
		lastFailure                     time.Time
		lastErr                         error
		consecutive                     int
	)
	deadline := time.Now().Add(budget)
	killed := false
	for time.Now().Before(deadline) {
		if !killed && time.Now().After(killAt) {
			killed = true
			aCancel()
			stopRun(t, aCancel, aErr, "replica-a")
		}
		_, err := poll.once(2 * time.Second)
		if err != nil {
			lastErr = err
			lastFailure = time.Now()
			consecutive = 0
			if killed {
				failuresAfter++
			} else {
				failuresBefore++
			}
		} else {
			consecutive++
			if killed {
				successesAfter++
			} else {
				successesBefore++
			}
		}
		time.Sleep(soakPollInterval)
	}

	if failuresBefore != 0 {
		t.Fatalf("%d unanswered requests before the replica was killed: the chain was not healthy to begin with", failuresBefore)
	}
	if successesAfter == 0 {
		t.Fatalf("no request was answered after the failover (failures %d, last error: %v)", failuresAfter, lastErr)
	}
	// Recovery: the last failure must be within the detection window of the
	// kill, not "eventually".
	recovery := lastFailure.Sub(killAt)
	if failuresAfter > 0 && recovery > 30*time.Second {
		t.Fatalf("failover took %s (last failure %s after the kill), want <= 30s: 3 idle misses of 3s plus one redial",
			recovery, recovery)
	}
	// And it must stay recovered: the run has to end in a green streak,
	// otherwise "recovery" was just the last failure happening early.
	if consecutive < 20 {
		t.Fatalf("the run ended with %d consecutive answers, want >= 20 (the chain did not stay up after failover)", consecutive)
	}
	if n := counterValue(t, met.Reconnects); n < 1 {
		t.Fatalf("tunnel reconnects = %v, want >= 1: the session never redialled", n)
	}
	if up := gaugeValue(t, met.TunnelUp); up != 1 {
		t.Fatalf("tunnel up gauge = %v, want 1 after failover", up)
	}

	stopRun(t, mgCancel, mgErr, "manager")
	stopRun(t, bCancel, bErr, "replica-b")

	// Teardown must not strand goroutines: 1000 answered requests over a
	// failover is exactly where a per-session leak would hide.
	waitGoroutines(t, baseline+8, 15*time.Second)

	t.Logf("soak: %s, failover after %s (%d failures in %s), %d answers after the kill, final streak %d",
		budget, recovery.Round(time.Millisecond), failuresAfter,
		time.Since(killAt).Round(time.Millisecond), successesAfter, consecutive)
}

// waitGoroutines blocks until the goroutine count drops to want (or fails).
func waitGoroutines(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		n := runtime.NumGoroutine()
		if n <= want {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d after teardown, want <= %d\n%s", n, want, buf)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
