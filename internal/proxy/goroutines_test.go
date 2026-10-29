// Regression test for the goroutine-per-message class the soak found.
//
// Two bugs, both invisible to functional tests because every request was
// still answered:
//
//   - passthrough Agent.bgctx built a context (and a watcher goroutine) per
//     SEND and discarded the cancel, so one goroutine leaked per request and
//     one per notification until shutdown.
//   - passthrough Agent.awaitAgentResp waited out its 15s timeout even after
//     the answer had arrived, holding a goroutine plus a pending entry per
//     unanswered-in-its-eyes request (rate × 15s goroutines steady state).
//
// This test is deliberately not soak-gated: 200 requests over about a second
// is enough to see +1 goroutine per request, so a regression fails in the
// normal suite. The long version, with heap and failover, is in soak_test.go.
package proxy

import (
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
)

// startTestChain brings up a two-proxy chain (passthrough or usm-translate)
// against a fake device and returns the manager's clear address plus a stop
// function that also asserts a clean exit.
func startTestChain(t *testing.T, usmTranslate bool) (mgrListen string, stop func()) {
	t.Helper()
	met := observ.NewMetrics()
	device := fakeAgent(t, "127.0.0.1:0")

	agentCfg := &config.Config{Role: config.RoleAgent}
	agentCfg.Defaults()
	agentCfg.Tunnel.Mode = "dtls"
	agentCfg.Tunnel.ListenAddr = freeUDPPort(t)
	agentCfg.Tunnel.PSK = "text:testpsk"
	agentCfg.Agent.AgentAddr = device.LocalAddr().String()
	if usmTranslate {
		agentCfg.Security.Mode = "usm-translate"
		agentCfg.Security.Users = testUsers()
		agentCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	}

	agCancel, agErr := startAgent(t, agentCfg, met)

	mgrCfg := &config.Config{Role: config.RoleManager}
	mgrCfg.Defaults()
	mgrCfg.Tunnel.Mode = "dtls"
	mgrCfg.Tunnel.DialAddrs = []string{agentCfg.Tunnel.ListenAddr}
	mgrCfg.Tunnel.PSK = "text:testpsk"
	mgrCfg.Manager.ListenAddr = freeUDPPort(t)
	if usmTranslate {
		mgrCfg.Security.Mode = "usm-translate"
		mgrCfg.Security.Users = testUsers()
		mgrCfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	}

	mgCancel, mgErr := startManager(t, mgrCfg, met)
	waitBound(t, mgrCfg.Manager.ListenAddr)

	var once sync.Once
	return mgrCfg.Manager.ListenAddr, func() {
		// Idempotent: the test defers stop and also calls it explicitly to
		// measure the post-shutdown goroutine count.
		once.Do(func() {
			stopRun(t, mgCancel, mgErr, "manager")
			stopRun(t, agCancel, agErr, "agent")
			_ = device.Close()
		})
	}
}

// TestNoPerRequestGoroutines serves a burst of requests and asserts neither
// the running chain nor the shutdown leaks a goroutine per message.
func TestNoPerRequestGoroutines(t *testing.T) {
	const requests = 200

	for _, mode := range []struct {
		name string
		usm  bool
	}{
		{"passthrough", false},
		{"usm-translate", true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			listen, stop := startTestChain(t, mode.usm)
			defer stop()

			poll := newChainPoll(t, listen)
			for i := 0; i < 5; i++ { // warm up the lazily started loops
				if _, err := poll.once(5 * time.Second); err != nil {
					t.Fatalf("warmup request %d: %v", i, err)
				}
			}
			steady := runtime.NumGoroutine()

			var maxSeen int
			for i := 0; i < requests; i++ {
				if _, err := poll.once(5 * time.Second); err != nil {
					t.Fatalf("request %d/%d: %v", i+1, requests, err)
				}
				if g := runtime.NumGoroutine(); g > maxSeen {
					maxSeen = g
				}
				time.Sleep(2 * time.Millisecond)
			}
			if maxSeen > steady+10 {
				t.Fatalf("goroutines %d at steady state, %d during %d requests: something is spawned per message",
					steady, maxSeen, requests)
			}

			stop()
			waitGoroutines(t, baseline+8, 15*time.Second)
		})
	}
}
