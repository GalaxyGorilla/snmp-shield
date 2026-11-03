package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
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
