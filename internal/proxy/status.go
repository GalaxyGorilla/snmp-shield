package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// statusDocument is the stable JSON shape served on /status. It is the
// daemon-level status contract the appliance layer builds on: no
// communities, USM secrets, PSKs or key material.
type statusDocument struct {
	OK           bool          `json:"ok"`
	Role         string        `json:"role"`
	SecurityMode string        `json:"security_mode"`
	TunnelMode   string        `json:"tunnel_mode,omitempty"`
	Version      string        `json:"version,omitempty"`
	ConfigHash   string        `json:"config_hash,omitempty"`
	Agents       []statusAgent `json:"agents"`
}

type statusAgent struct {
	Name       string         `json:"name"`
	Listen     string         `json:"listen,omitempty"`
	Upstream   string         `json:"upstream,omitempty"`
	ReadOnly   bool           `json:"read_only"`
	AllowCount int            `json:"allow_count,omitempty"`
	RatePerSec int            `json:"rate_per_sec,omitempty"`
	Counters   statusCounters `json:"counters"`
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

// newStatusHandler builds the /status handler. Counters are read from the
// same per-agent views the translators update, so the document stays
// consistent with Prometheus and the SNMP MIB.
func newStatusHandler(opts Options, met *observ.Metrics) http.Handler {
	hash := ""
	if opts.ConfigPath != "" {
		if data, err := os.ReadFile(opts.ConfigPath); err == nil {
			sum := sha256.Sum256(data)
			hash = hex.EncodeToString(sum[:])
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := statusDocument{
			OK:           true,
			Role:         string(opts.Config.Role),
			SecurityMode: opts.Config.Security.Mode,
			TunnelMode:   opts.Config.Tunnel.Mode,
			Version:      opts.Version,
			ConfigHash:   hash,
		}
		if doc.Version == "" {
			doc.Version = "dev"
		}
		if opts.Config.HasAgents() {
			for _, a := range opts.Config.Agents {
				name := a.EffectiveName()
				gw := opts.Config.EffectiveGateway(a)
				acc := opts.Config.EffectiveAccess(a)
				doc.Agents = append(doc.Agents, statusAgent{
					Name:       name,
					Listen:     gw.ListenAddr,
					Upstream:   gw.AgentAddr,
					ReadOnly:   acc.ReadOnly,
					AllowCount: len(acc.Allow),
					RatePerSec: acc.RatePerSec,
					Counters:   countersFrom(met.ForAgent(name)),
				})
			}
		} else {
			listen, upstream := statusEndpoints(opts.Config)
			doc.Agents = []statusAgent{{
				Name:       "default",
				Listen:     listen,
				Upstream:   upstream,
				ReadOnly:   opts.Config.Access.ReadOnly,
				AllowCount: len(opts.Config.Access.Allow),
				RatePerSec: opts.Config.Access.RatePerSec,
				Counters:   countersFrom(met),
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
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
