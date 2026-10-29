package proxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// reload_e2e_test.go — the operator's reload path end to end.
//
// reload_test.go pins applyReload against a synthetic *config.Config, which
// leaves the parts an operator actually touches untested: the YAML file on
// disk, config.Load's role handling, the reloadLoop's channel select, and —
// the one that matters — whether the swapped policy is visible ON THE WIRE
// while the proxy keeps serving.
//
// The OS signal itself is not delivered here (that would fire into the test
// binary's process); everything from the SIGHUP handler inwards is real, and
// TESTING.md records the remaining gap.

// reloadFixture writes a valid usm-gateway YAML file and can rewrite it.
type reloadFixture struct {
	path       string
	listenAddr string
	agentAddr  string
	enginePath string
}

// write (re)writes the config file with the given access block and listen
// address. Empty accessBlock means "no access section" (allow everything),
// empty listenAddr keeps the original front leg.
func (f *reloadFixture) write(t *testing.T, accessBlock, listenAddr string) {
	t.Helper()
	if listenAddr == "" {
		listenAddr = f.listenAddr
	}
	body := fmt.Sprintf(`role: gateway
gateway:
  listen_addr: %q
  agent_addr: %q
  agent_community: public
security:
  mode: usm-gateway
  engine_store: %q
  users:
    - name: proxy
      auth_protocol: sha
      auth_passphrase: authpass
      priv_protocol: aes
      priv_passphrase: privpass
%s`, listenAddr, f.agentAddr, f.enginePath, accessBlock)
	if err := os.WriteFile(f.path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func newReloadFixture(t *testing.T) *reloadFixture {
	t.Helper()
	return &reloadFixture{
		path:       filepath.Join(t.TempDir(), "gateway.yaml"),
		listenAddr: freeUDPPort(t),
		enginePath: filepath.Join(t.TempDir(), "engine.json"),
	}
}

// TestReloadFromDiskTakesEffectOnWire drives the full sequence an operator
// performs during an incident: edit access, systemctl reload, expect the
// next SET to be refused — with the legacy device never seeing a write.
func TestReloadFromDiskTakesEffectOnWire(t *testing.T) {
	met := observ.NewMetrics()
	agent, sets := countingFakeAgent(t, "127.0.0.1:0")
	defer agent.Close()

	f := newReloadFixture(t)
	f.agentAddr = agent.LocalAddr().String()
	f.write(t, "", "")

	cfg, err := config.Load(f.path, config.RoleGateway)
	if err != nil {
		t.Fatalf("the fixture config is not loadable: %v", err)
	}
	pol, err := cfg.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	h := access.NewHolder(pol)

	core, logs := observer.New(zapcore.DebugLevel)
	opts := Options{Config: cfg, ConfigPath: f.path, Access: h, Log: zap.New(core), Version: "test"}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- runGateway(ctx, opts, met) }()
	waitBound(t, f.listenAddr)

	g := gosnmpV3(t, f.listenAddr)
	defer g.Conn.Close()

	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("GET before reload: %v", err)
	}
	setVar := []gosnmp.SnmpPDU{{
		Name:  "1.3.6.1.2.1.1.5.0",
		Type:  gosnmp.OctetString,
		Value: "renamed",
	}}
	if res, serr := g.Set(setVar); serr != nil || res.Error != gosnmp.NoError {
		t.Fatalf("SET before reload: err=%v status=%v", serr, res.Error)
	}
	if n := sets.Load(); n != 1 {
		t.Fatalf("the allowed SET reached the agent %d time(s), want 1", n)
	}

	// --- operator locks the write path and sends SIGHUP ---------------------
	f.write(t, "access:\n  read_only: true\n", "")
	reloadConfig(opts)

	if !h.Get().ReadOnly() {
		t.Fatal("the reloaded read-only policy is not installed")
	}
	if logs.FilterMessage("SIGHUP: configuration reloaded").Len() == 0 {
		t.Fatal("the reload was not logged as applied")
	}
	entry := logs.FilterMessage("SIGHUP: configuration reloaded").All()[0]
	if got := entry.ContextMap()["access"]; got != "read-only, 0 write rules" {
		t.Fatalf("reload log says access=%v, want the reloaded policy", got)
	}

	// The next datagram must already see it — that is the whole promise of
	// a per-datagram holder — and the device must never see the write.
	res, serr := g.Set(setVar)
	if serr != nil {
		t.Fatalf("refused SET returned a transport error instead of an answer: %v", serr)
	}
	if res.Error != gosnmp.NotWritable {
		t.Fatalf("SET after reload: status=%v, want notWritable", res.Error)
	}
	if n := sets.Load(); n != 1 {
		t.Fatalf("the refused SET reached the agent (sets=%d, want 1)", n)
	}
	// Reads keep working: read-only is a write lock, not an outage.
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("GET under the reloaded read-only policy: %v", err)
	}

	// --- a typo must not relax the policy ----------------------------------
	f.write(t, "access:\n  write_policy:\n    default: deny\n", "")
	reloadConfig(opts)
	if !h.Get().ReadOnly() {
		t.Fatal("an invalid access section replaced the running policy")
	}
	if logs.FilterMessage("reload: new config invalid, keeping the running configuration").Len() == 0 {
		t.Fatal("an invalid config on SIGHUP was not logged")
	}
	if res, serr := g.Set(setVar); serr != nil || res.Error != gosnmp.NotWritable {
		t.Fatalf("SET after an invalid reload: err=%v status=%v, want notWritable", serr, res.Error)
	}
	if n := sets.Load(); n != 1 {
		t.Fatalf("the refused SET reached the agent (sets=%d, want 1)", n)
	}

	// --- a restart-only change is reported, not silently ignored ----------
	f.write(t, "access:\n  read_only: true\n", freeUDPPort(t))
	reloadConfig(opts)
	if logs.FilterMessageSnippet("gateway block changed (restart required)").Len() == 0 {
		t.Fatalf("a changed listen_addr was not reported as restart-required; logs: %v", logs.All())
	}
	// The running listener was NOT rebound: the original address still serves.
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("the running front leg stopped serving after a restart-required reload: %v", err)
	}

	// --- flags mode: SIGHUP is a logged no-op, never a policy reset --------
	flagsOpts := opts
	flagsOpts.ConfigPath = ""
	f.write(t, "", "")
	reloadConfig(flagsOpts)
	if !h.Get().ReadOnly() {
		t.Fatal("a flags-mode SIGHUP reset the policy")
	}
	if logs.FilterMessageSnippet("SIGHUP ignored").Len() == 0 {
		t.Fatal("a flags-mode SIGHUP was not reported")
	}

	g.Conn.Close()
	stopRun(t, cancel, errCh, "gateway")
}

// TestReloadLoopConsumesHUPSignals pins the loop wiring: a signal on the
// channel applies the file, and closing the shutdown channel ends the
// goroutine (Run's defer order relies on it, and a leaked reload goroutine
// would outlive every test).
func TestReloadLoopConsumesHUPSignals(t *testing.T) {
	f := newReloadFixture(t)
	f.agentAddr = "127.0.0.1:1" // never dialled: nothing serves in this test
	f.write(t, "", "")

	cfg, err := config.Load(f.path, config.RoleGateway)
	if err != nil {
		t.Fatalf("the fixture config is not loadable: %v", err)
	}
	h := access.NewHolder(nil)
	opts := Options{Config: cfg, ConfigPath: f.path, Access: h, Log: zap.NewNop()}

	hupCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		reloadLoop(hupCh, opts, done)
		close(exited)
	}()

	f.write(t, "access:\n  read_only: true\n", "")
	hupCh <- syscall.SIGHUP

	deadline := time.Now().Add(5 * time.Second)
	for !h.Get().ReadOnly() {
		if time.Now().After(deadline) {
			t.Fatal("reloadLoop did not apply the file after a SIGHUP")
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(done)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("reloadLoop did not return when the process shut down")
	}
}
