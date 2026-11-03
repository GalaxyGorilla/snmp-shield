package proxy

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
	"github.com/gosnmp/gosnmp"
)

const (
	faultSysDescr = "1.3.6.1.2.1.1.1.0"
	faultSysName  = "1.3.6.1.2.1.1.5.0"
)

// startUSMGatewayTo runs the single-box USM gateway against upstream (a
// fake agent or a fault relay) and waits for its front listener.
func startUSMGatewayTo(t *testing.T, upstream string) (front string, cancel context.CancelFunc, errCh chan error, met *observ.Metrics) {
	t.Helper()
	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Security.Users = testUsers()
	cfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	cfg.Gateway.ListenAddr = freeUDPPort(t)
	cfg.Gateway.AgentAddr = upstream
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	met = observ.NewMetrics()
	cancel, errCh = startGateway(t, cfg, met)
	return cfg.Gateway.ListenAddr, cancel, errCh, met
}

// TestUSMGatewayRetriesAfterResponseLoss proves the device leg survives a
// lost answer: the client retransmits, the proxy forwards the retry, and the
// second answer is correlated and returned. A pending entry that was never
// cleaned up would also make this pass, so the follow-up asserts teardown.
func TestUSMGatewayRetriesAfterResponseLoss(t *testing.T) {
	agent := testkit.NewAgent(t, testkit.AgentOptions{})
	var dropped atomic.Bool
	relay := testkit.NewFaultyUDPRelay(t, agent.Addr(), func(dir testkit.FaultDirection, seq int, _ []byte) testkit.FaultAction {
		if dir == testkit.FaultToDownstream && seq == 1 {
			dropped.Store(true)
			return testkit.FaultAction{Drop: true}
		}
		return testkit.FaultAction{}
	})
	front, cancel, errCh, _ := startUSMGatewayTo(t, relay.Addr())

	g := gosnmpV3(t, front)
	g.Timeout = 500 * time.Millisecond
	g.Retries = 2
	defer g.Conn.Close()

	baseline := runtime.NumGoroutine()
	res, err := g.Get([]string{faultSysDescr})
	if err != nil {
		t.Fatalf("GET after a lost response: %v", err)
	}
	if !dropped.Load() {
		t.Fatal("the relay did not drop the first response")
	}
	if len(res.Variables) != 1 || res.Variables[0].Name != "."+faultSysDescr {
		t.Fatalf("answer = %+v", res.Variables)
	}

	stopRun(t, cancel, errCh, "usm gateway")
	waitGoroutines(t, baseline+8, 5*time.Second)
}

// TestUSMGatewayIgnoresDuplicateResponses keeps duplicate answers on the
// device leg. The proxy must deliver one answer per request and drop the
// duplicate without a panic or a leaked pending entry.
func TestUSMGatewayIgnoresDuplicateResponses(t *testing.T) {
	agent := testkit.NewAgent(t, testkit.AgentOptions{})
	relay := testkit.NewFaultyUDPRelay(t, agent.Addr(), func(dir testkit.FaultDirection, _ int, _ []byte) testkit.FaultAction {
		if dir == testkit.FaultToDownstream {
			return testkit.FaultAction{Duplicate: true}
		}
		return testkit.FaultAction{}
	})
	front, cancel, errCh, _ := startUSMGatewayTo(t, relay.Addr())

	g := gosnmpV3(t, front)
	defer g.Conn.Close()
	baseline := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		res, err := g.Get([]string{faultSysDescr})
		if err != nil {
			t.Fatalf("GET %d with duplicate answers: %v", i, err)
		}
		if len(res.Variables) != 1 {
			t.Fatalf("GET %d returned %d varbinds", i, len(res.Variables))
		}
	}

	stopRun(t, cancel, errCh, "usm gateway")
	waitGoroutines(t, baseline+8, 5*time.Second)
}

// TestUSMGatewayReorderedResponses delays the first answer past the second.
// The proxy's pending map is keyed by request-id, not arrival order, so both
// clients must still get the object they asked for.
func TestUSMGatewayReorderedResponses(t *testing.T) {
	agent := testkit.NewAgent(t, testkit.AgentOptions{})
	relay := testkit.NewFaultyUDPRelay(t, agent.Addr(), func(dir testkit.FaultDirection, seq int, _ []byte) testkit.FaultAction {
		if dir == testkit.FaultToDownstream && seq == 1 {
			return testkit.FaultAction{Delay: 250 * time.Millisecond}
		}
		return testkit.FaultAction{}
	})
	front, cancel, errCh, _ := startUSMGatewayTo(t, relay.Addr())

	a := gosnmpV3(t, front)
	b := gosnmpV3(t, front)
	defer a.Conn.Close()
	defer b.Conn.Close()

	// Send A first and wait until the device has answered it (the relay is
	// holding that answer), then send B. B's answer overtakes A's.
	type result struct {
		vars []gosnmp.SnmpPDU
		err  error
	}
	aCh := make(chan result, 1)
	go func() {
		res, err := a.Get([]string{faultSysDescr})
		var vars []gosnmp.SnmpPDU
		if res != nil {
			vars = res.Variables
		}
		aCh <- result{vars: vars, err: err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for agent.GETs() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if agent.GETs() == 0 {
		t.Fatal("the first request never reached the device")
	}
	resB, err := b.Get([]string{faultSysName})
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	ra := <-aCh
	if ra.err != nil {
		t.Fatalf("delayed GET: %v", ra.err)
	}
	if len(ra.vars) != 1 || ra.vars[0].Name != "."+faultSysDescr {
		t.Fatalf("delayed answer = %+v", ra.vars)
	}
	if len(resB.Variables) != 1 || resB.Variables[0].Name != "."+faultSysName {
		t.Fatalf("overtaking answer = %+v", resB.Variables)
	}

	stopRun(t, cancel, errCh, "usm gateway")
}

// TestUSMGatewayConcurrentManagers is the fan-in shape the soak does not
// cover: many independent v3 managers hitting the same gateway at once.
// It exercises the pending map, the per-request goroutine and the shared
// device socket under real concurrency.
func TestUSMGatewayConcurrentManagers(t *testing.T) {
	agent := testkit.NewAgent(t, testkit.AgentOptions{})
	front, cancel, errCh, _ := startUSMGatewayTo(t, agent.Addr())

	const managers = 16
	const rounds = 10
	clients := make([]*gosnmp.GoSNMP, managers)
	for i := range clients {
		clients[i] = gosnmpV3(t, front)
	}
	defer func() {
		for _, g := range clients {
			g.Conn.Close()
		}
	}()

	baseline := runtime.NumGoroutine()
	var wg sync.WaitGroup
	var failures atomic.Int32
	for _, g := range clients {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				if _, err := g.Get([]string{faultSysDescr}); err != nil {
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of %d concurrent GETs failed", n, managers*rounds)
	}
	if got := agent.GETs(); got < managers*rounds {
		t.Fatalf("device saw %d GETs, want at least %d", got, managers*rounds)
	}

	stopRun(t, cancel, errCh, "usm gateway")
	waitGoroutines(t, baseline+8, 5*time.Second)
}
