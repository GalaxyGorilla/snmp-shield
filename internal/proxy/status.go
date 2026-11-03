package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// statusDocument is the stable JSON shape served on /status. It is the
// daemon-level status contract the appliance layer builds on: no
// communities, USM secrets, PSKs or key material.
//
// Ready is true only after every configured listener has bound. The
// config hash and revision describe the last successfully loaded file;
// reload reports the outcome of the most recent SIGHUP (including changes
// that need a restart). A failed reload keeps the previous hash/revision
// and records the error, so a status page can never claim a file is live
// when it is not.
type statusDocument struct {
	OK             bool          `json:"ok"`
	Ready          bool          `json:"ready"`
	Role           string        `json:"role"`
	SecurityMode   string        `json:"security_mode"`
	TunnelMode     string        `json:"tunnel_mode,omitempty"`
	Version        string        `json:"version,omitempty"`
	ConfigHash     string        `json:"config_hash,omitempty"`
	ConfigRevision uint64        `json:"config_revision"`
	Reload         statusReload  `json:"reload"`
	Agents         []statusAgent `json:"agents"`
}

// statusReload is the process-wide reload result. Attempts counts every
// SIGHUP that tried to load a file; Applied counts those that parsed and
// were installed (restart-only warnings do not make a reload fail).
type statusReload struct {
	Attempts        int      `json:"attempts"`
	Applied         int      `json:"applied"`
	LastOK          bool     `json:"last_ok"`
	LastError       string   `json:"last_error,omitempty"`
	RestartRequired []string `json:"restart_required,omitempty"`
}

// statusAgentReload is the per-entry view: whether that entry's live
// access policy is the one from the active file, and which of its
// settings still need a restart.
type statusAgentReload struct {
	PolicyApplied   bool     `json:"policy_applied"`
	RestartRequired []string `json:"restart_required,omitempty"`
}

type statusAgent struct {
	Name       string            `json:"name"`
	Listen     string            `json:"listen,omitempty"`
	Upstream   string            `json:"upstream,omitempty"`
	Ready      bool              `json:"ready"`
	ReadOnly   bool              `json:"read_only"`
	AllowCount int               `json:"allow_count,omitempty"`
	RatePerSec int               `json:"rate_per_sec,omitempty"`
	Counters   statusCounters    `json:"counters"`
	Reload     statusAgentReload `json:"reload"`
}

type statusCounters struct {
	RequestsForwarded     uint64  `json:"requests_forwarded"`
	RequestErrors         uint64  `json:"request_errors"`
	NotificationsRelayed  uint64  `json:"notifications_relayed"`
	NotificationsFiltered uint64  `json:"notifications_filtered"`
	Drops                 uint64  `json:"drops"`
	ACLDenied             uint64  `json:"acl_denied"`
	WritesDenied          uint64  `json:"writes_denied"`
	RateLimited           uint64  `json:"rate_limited"`
	LatencyCount          uint64  `json:"latency_count"`
	LatencySumSeconds     float64 `json:"latency_sum_seconds"`
}

// statusState is the live state behind /status. The config pointer is
// replaced only by a successful reload, and only with the parts that were
// actually installed: a changed listener stays at its running value while
// the reload result names it as restart-required.
type statusState struct {
	mu          sync.RWMutex
	cfg         *config.Config
	hash        string
	revision    uint64
	ready       map[string]bool
	reload      statusReload
	agentReload map[string]statusAgentReload
}

// statusSnapshot is a consistent copy for one response.
type statusSnapshot struct {
	cfg         *config.Config
	hash        string
	revision    uint64
	ready       map[string]bool
	reload      statusReload
	agentReload map[string]statusAgentReload
}

func newStatusState(opts Options) *statusState {
	s := &statusState{
		cfg:         opts.Config,
		hash:        configFileHash(opts.ConfigPath),
		revision:    1,
		ready:       make(map[string]bool),
		reload:      statusReload{LastOK: true},
		agentReload: make(map[string]statusAgentReload),
	}
	for _, name := range statusNames(opts.Config) {
		s.ready[name] = false
		s.agentReload[name] = statusAgentReload{PolicyApplied: true}
	}
	return s
}

// statusNames lists the running entries in config order. Single-agent
// shapes use the synthetic "default" name, matching the metrics and MIB
// views.
func statusNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	if cfg.HasAgents() {
		names := make([]string, 0, len(cfg.Agents))
		for _, a := range cfg.Agents {
			names = append(names, a.EffectiveName())
		}
		return names
	}
	return []string{"default"}
}

// markAllReady is called only after every configured listener has bound.
func (s *statusState) markAllReady() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.ready {
		s.ready[name] = true
	}
}

// reloadAttempt records a SIGHUP that reached the file-loading step.
func (s *statusState) reloadAttempt() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload.Attempts++
}

// reloadFailed records a file that did not load. The active config,
// hash and revision are deliberately left untouched.
func (s *statusState) reloadFailed(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload.LastOK = false
	if err != nil {
		s.reload.LastError = err.Error()
	} else {
		s.reload.LastError = "reload failed"
	}
}

// reloadApplied records a file that loaded and was installed. cfg must
// already be the active view (running listeners plus the newly applied
// policy), not the raw file.
func (s *statusState) reloadApplied(cfg *config.Config, hash string, restart []string, perAgent map[string]agentReloadResult) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.hash = hash
	s.revision++
	s.reload.Applied++
	s.reload.LastOK = true
	s.reload.LastError = ""
	s.reload.RestartRequired = append([]string(nil), restart...)
	for name, res := range perAgent {
		if _, running := s.ready[name]; !running {
			continue
		}
		s.agentReload[name] = statusAgentReload{
			PolicyApplied:   res.policyApplied,
			RestartRequired: append([]string(nil), res.restartRequired...),
		}
	}
}

func (s *statusState) snapshot() statusSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ready := make(map[string]bool, len(s.ready))
	for name, ok := range s.ready {
		ready[name] = ok
	}
	perAgent := make(map[string]statusAgentReload, len(s.agentReload))
	for name, res := range s.agentReload {
		res.RestartRequired = append([]string(nil), res.RestartRequired...)
		perAgent[name] = res
	}
	reload := s.reload
	reload.RestartRequired = append([]string(nil), s.reload.RestartRequired...)
	return statusSnapshot{
		cfg:         s.cfg,
		hash:        s.hash,
		revision:    s.revision,
		ready:       ready,
		reload:      reload,
		agentReload: perAgent,
	}
}

// newStatusHandler builds the /status handler. Counters are read from the
// same per-agent views the translators update, so the document stays
// consistent with Prometheus and the SNMP MIB.
func newStatusHandler(opts Options, met *observ.Metrics) http.Handler {
	st := opts.status
	if st == nil {
		// Direct construction (tests, embedders) keeps the previous
		// behavior: the supplied config is treated as already active.
		st = newStatusState(opts)
		st.markAllReady()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := st.snapshot()
		cfg := snap.cfg
		if cfg == nil {
			http.Error(w, "status unavailable", http.StatusServiceUnavailable)
			return
		}
		allReady := len(snap.ready) > 0
		for _, ok := range snap.ready {
			if !ok {
				allReady = false
				break
			}
		}
		doc := statusDocument{
			OK:             allReady,
			Ready:          allReady,
			Role:           string(cfg.Role),
			SecurityMode:   cfg.Security.Mode,
			TunnelMode:     cfg.Tunnel.Mode,
			Version:        opts.Version,
			ConfigHash:     snap.hash,
			ConfigRevision: snap.revision,
			Reload:         snap.reload,
		}
		if doc.Version == "" {
			doc.Version = "dev"
		}
		if cfg.HasAgents() {
			for _, a := range cfg.Agents {
				name := a.EffectiveName()
				gw := cfg.EffectiveGateway(a)
				acc := cfg.EffectiveAccess(a)
				doc.Agents = append(doc.Agents, statusAgent{
					Name:       name,
					Listen:     gw.ListenAddr,
					Upstream:   gw.AgentAddr,
					Ready:      snap.ready[name],
					ReadOnly:   acc.ReadOnly,
					AllowCount: len(acc.Allow),
					RatePerSec: acc.RatePerSec,
					Counters:   countersFrom(met.ForAgent(name)),
					Reload:     snap.agentReload[name],
				})
			}
		} else {
			listen, upstream := statusEndpoints(cfg)
			doc.Agents = []statusAgent{{
				Name:       "default",
				Listen:     listen,
				Upstream:   upstream,
				Ready:      snap.ready["default"],
				ReadOnly:   cfg.Access.ReadOnly,
				AllowCount: len(cfg.Access.Allow),
				RatePerSec: cfg.Access.RatePerSec,
				Counters:   countersFrom(met),
				Reload:     snap.agentReload["default"],
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

// configFileHash hashes the file an operator last pointed the process at.
// A read error is not fatal here: the hash is informational, and the
// load path has already reported the real error.
func configFileHash(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func statusEndpoints(cfg *config.Config) (listen, upstream string) {
	switch cfg.Role {
	case config.RoleGateway:
		return cfg.Gateway.ListenAddr, cfg.Gateway.AgentAddr
	case config.RoleManager:
		return cfg.Manager.ListenAddr, strings.Join(cfg.DialEndpoints(), ",")
	case config.RoleAgent:
		return cfg.Tunnel.ListenAddr, cfg.Agent.AgentAddr
	}
	return "", ""
}

func countersFrom(m *observ.Metrics) statusCounters {
	list := m.PerAgentCounterList()
	val := func(i int) uint64 {
		if i >= len(list) || list[i] == nil {
			return 0
		}
		return statusCounterValue(list[i])
	}
	count, sum := histogramValues(m.ForwardLatency)
	return statusCounters{
		RequestsForwarded:     val(0),
		RequestErrors:         val(1),
		NotificationsRelayed:  val(2),
		NotificationsFiltered: val(3),
		Drops:                 val(4),
		ACLDenied:             val(5),
		WritesDenied:          val(6),
		RateLimited:           val(7),
		LatencyCount:          count,
		LatencySumSeconds:     sum,
	}
}

func statusCounterValue(c prometheus.Counter) uint64 {
	m := &dto.Metric{}
	if c.Write(m) != nil || m.Counter == nil {
		return 0
	}
	v := m.Counter.GetValue()
	if v < 0 {
		return 0
	}
	return uint64(v)
}

func histogramValues(h prometheus.Histogram) (uint64, float64) {
	if h == nil {
		return 0, 0
	}
	m := &dto.Metric{}
	if h.Write(m) != nil || m.Histogram == nil {
		return 0, 0
	}
	var count uint64
	var sum float64
	if m.Histogram.SampleCount != nil {
		count = *m.Histogram.SampleCount
	}
	if m.Histogram.SampleSum != nil {
		sum = *m.Histogram.SampleSum
	}
	return count, sum
}
