package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"go.uber.org/zap"
)

func TestStatusHandlerMultiAgent(t *testing.T) {
	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Security.Users = testUsers()
	cfg.Security.EngineStoreDir = t.TempDir()
	cfg.Agents = []config.AgentEntry{
		{
			Name:       "plc",
			ListenAddr: "10.0.0.10:161",
			AgentAddr:  "10.0.0.50:161",
			Access: &config.Access{
				ReadOnly:   true,
				Allow:      []string{"10.8.0.0/24"},
				RatePerSec: 50,
			},
		},
		{Name: "ahu", ListenAddr: "10.0.0.11:161", AgentAddr: "10.0.0.51:161"},
	}
	met := observ.NewMetrics()
	plc := met.ForAgent("plc")
	plc.ReqForwarded.Inc()
	plc.ReqForwarded.Inc()
	plc.WritesDenied.Inc()
	plc.ForwardLatency.Observe(0.5)

	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, []byte("security:\n  mode: usm-gateway\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newStatusHandler(Options{Config: cfg, ConfigPath: path, Version: "test"}, met)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))

	var doc statusDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode status: %v\n%s", err, rec.Body.String())
	}
	if !doc.OK || doc.Role != "gateway" || doc.SecurityMode != "usm-gateway" || doc.Version != "test" {
		t.Fatalf("status header = %+v", doc)
	}
	if doc.ConfigHash == "" {
		t.Fatal("config_hash is empty")
	}
	if len(doc.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(doc.Agents))
	}
	plcDoc := doc.Agents[0]
	if plcDoc.Name != "plc" || plcDoc.Listen != "10.0.0.10:161" || plcDoc.Upstream != "10.0.0.50:161" {
		t.Fatalf("plc status = %+v", plcDoc)
	}
	if !plcDoc.ReadOnly || plcDoc.AllowCount != 1 || plcDoc.RatePerSec != 50 {
		t.Fatalf("plc policy = %+v", plcDoc)
	}
	if plcDoc.Counters.RequestsForwarded != 2 || plcDoc.Counters.WritesDenied != 1 {
		t.Fatalf("plc counters = %+v", plcDoc.Counters)
	}
	if plcDoc.Counters.LatencyCount != 1 || plcDoc.Counters.LatencySumSeconds != 0.5 {
		t.Fatalf("plc latency = %+v", plcDoc.Counters)
	}
	if doc.Agents[1].Name != "ahu" {
		t.Fatalf("second agent = %+v", doc.Agents[1])
	}
	// Never leak credentials or key material.
	body := rec.Body.String()
	for _, secret := range []string{"authpass", "privpass", "psk", "passphrase"} {
		if strings.Contains(body, secret) {
			t.Fatalf("status leaks %q: %s", secret, body)
		}
	}
}

func TestStatusHandlerSingleAgent(t *testing.T) {
	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Gateway.ListenAddr = ":161"
	cfg.Gateway.AgentAddr = "10.0.0.50:161"
	met := observ.NewMetrics()
	h := newStatusHandler(Options{Config: cfg, Version: "test"}, met)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	var doc statusDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Agents) != 1 || doc.Agents[0].Name != "default" {
		t.Fatalf("single-agent status = %+v", doc.Agents)
	}
	if doc.Agents[0].Listen != ":161" || doc.Agents[0].Upstream != "10.0.0.50:161" {
		t.Fatalf("single-agent endpoints = %+v", doc.Agents[0])
	}
}

func decodeStatus(t *testing.T, h http.Handler) statusDocument {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	var doc statusDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode status: %v\n%s", err, rec.Body.String())
	}
	return doc
}

func TestStatusReadyOnlyAfterListenersBind(t *testing.T) {
	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Gateway.ListenAddr = "127.0.0.1:161"
	cfg.Gateway.AgentAddr = "127.0.0.1:1161"
	opts := Options{Config: cfg, Version: "test"}
	opts.status = newStatusState(opts)
	h := newStatusHandler(opts, observ.NewMetrics())

	doc := decodeStatus(t, h)
	if doc.OK || doc.Ready {
		t.Fatalf("status is ready before any listener bound: %+v", doc)
	}
	if doc.Agents[0].Ready {
		t.Fatalf("default entry is ready before any listener bound: %+v", doc.Agents[0])
	}

	opts.status.markAllReady()
	doc = decodeStatus(t, h)
	if !doc.OK || !doc.Ready {
		t.Fatalf("status is not ready after listeners bound: %+v", doc)
	}
	if !doc.Agents[0].Ready {
		t.Fatalf("default entry is not ready after listeners bound: %+v", doc.Agents[0])
	}
}

func TestStatusTracksReloadResult(t *testing.T) {
	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Security.Users = testUsers()
	cfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	cfg.Gateway.ListenAddr = "127.0.0.1:161"
	cfg.Gateway.AgentAddr = "127.0.0.1:1161"
	cfg.Access.ReadOnly = false

	path := filepath.Join(t.TempDir(), "gateway.yaml")
	write := func(access string) {
		body := "role: gateway\n" +
			"gateway:\n  listen_addr: \"127.0.0.1:161\"\n  agent_addr: \"127.0.0.1:1161\"\n" +
			"security:\n  mode: usm-gateway\n  engine_store: \"" + cfg.Security.EngineStore + "\"\n" +
			"  users:\n    - name: proxy\n      auth_protocol: sha\n      auth_passphrase: authpass\n" +
			"      priv_protocol: aes\n      priv_passphrase: privpass\n" + access
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("")

	loaded, err := config.Load(path, config.RoleGateway)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	opts := Options{
		Config:     loaded,
		ConfigPath: path,
		Access:     access.NewHolder(nil),
		Log:        zap.NewNop(),
		Version:    "test",
	}
	opts.status = newStatusState(opts)
	opts.status.markAllReady()
	h := newStatusHandler(opts, observ.NewMetrics())

	before := decodeStatus(t, h)
	if before.ConfigHash == "" || before.ConfigRevision != 1 {
		t.Fatalf("startup status = %+v", before)
	}
	if before.Reload.Attempts != 0 || !before.Reload.LastOK {
		t.Fatalf("startup reload = %+v", before.Reload)
	}

	// A successful reload changes the hash/revision and reports the
	// reloadable policy as applied.
	write("access:\n  read_only: true\n")
	reloadConfig(opts)
	after := decodeStatus(t, h)
	if after.ConfigHash == before.ConfigHash {
		t.Fatal("config_hash did not change after a successful reload")
	}
	if after.ConfigRevision != before.ConfigRevision+1 {
		t.Fatalf("config_revision = %d, want %d", after.ConfigRevision, before.ConfigRevision+1)
	}
	if after.Reload.Attempts != 1 || after.Reload.Applied != 1 || !after.Reload.LastOK {
		t.Fatalf("reload = %+v", after.Reload)
	}
	if !after.Agents[0].ReadOnly || !after.Agents[0].Reload.PolicyApplied {
		t.Fatalf("reloaded policy not reflected in status: %+v", after.Agents[0])
	}

	// A bad file is reported without changing the active hash/revision or
	// the running policy.
	badHash := after.ConfigHash
	if err := os.WriteFile(path, []byte("role: gateway\nsecurity:\n  mode: usm-gateway\n  users: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadConfig(opts)
	failed := decodeStatus(t, h)
	if failed.ConfigHash != badHash || failed.ConfigRevision != after.ConfigRevision {
		t.Fatalf("a failed reload changed the active config: %+v", failed)
	}
	if failed.Reload.LastOK || failed.Reload.LastError == "" {
		t.Fatalf("failed reload not reported: %+v", failed.Reload)
	}
	if !failed.Agents[0].ReadOnly {
		t.Fatal("a failed reload changed the running policy")
	}
}

func TestStatusPerAgentReloadRestartRequired(t *testing.T) {
	cur := &config.Config{Role: config.RoleGateway, Security: config.Security{Mode: "usm-gateway"}}
	cur.Defaults()
	cur.Security.Users = testUsers()
	cur.Security.EngineStoreDir = t.TempDir()
	cur.Agents = []config.AgentEntry{
		{Name: "plc", ListenAddr: "127.0.0.1:1161", AgentAddr: "127.0.0.1:2161"},
	}
	if err := cur.Validate(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "gateway.yaml")
	body := "role: gateway\n" +
		"security:\n  mode: usm-gateway\n  engine_store_dir: \"" + cur.Security.EngineStoreDir + "\"\n" +
		"  users:\n    - name: proxy\n      auth_protocol: sha\n      auth_passphrase: authpass\n" +
		"      priv_protocol: aes\n      priv_passphrase: privpass\n" +
		"agents:\n  - name: plc\n    listen_addr: \"127.0.0.1:1162\"\n    agent_addr: \"127.0.0.1:2161\"\n" +
		"    access:\n      read_only: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	holders := map[string]*access.Holder{"plc": access.NewHolder(nil)}
	opts := Options{Config: cur, ConfigPath: path, AgentAccess: holders, Log: zap.NewNop(), Version: "test"}
	opts.status = newStatusState(opts)
	opts.status.markAllReady()
	h := newStatusHandler(opts, observ.NewMetrics())

	reloadConfig(opts)
	doc := decodeStatus(t, h)
	if doc.ConfigRevision != 2 {
		t.Fatalf("config_revision = %d, want 2", doc.ConfigRevision)
	}
	if len(doc.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(doc.Agents))
	}
	a := doc.Agents[0]
	if a.Name != "plc" || !a.ReadOnly || !a.Reload.PolicyApplied {
		t.Fatalf("plc status = %+v", a)
	}
	if a.Listen != "127.0.0.1:1161" {
		t.Fatalf("status reported the new, unbound listener %q", a.Listen)
	}
	found := false
	for _, r := range a.Reload.RestartRequired {
		if strings.Contains(r, "listener/agent changed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("plc restart_required = %v, want listener/agent changed", a.Reload.RestartRequired)
	}
	if len(doc.Reload.RestartRequired) == 0 {
		t.Fatal("process reload.restart_required is empty")
	}
	// Never leak credentials or key material.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	for _, secret := range []string{"authpass", "privpass", "psk", "passphrase"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("status leaks %q: %s", secret, rec.Body.String())
		}
	}
}
