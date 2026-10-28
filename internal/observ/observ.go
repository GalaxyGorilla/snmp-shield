// Package observ provides the shared logging (zap) and Prometheus
// metrics baseline for both proxy roles.
package observ

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Log builds the process logger. level is "debug", "info" or "error";
// development toggles human-friendly console output.
func Log(level string, development bool) (*zap.Logger, error) {
	lvl := zap.NewAtomicLevelAt(zap.InfoLevel)
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	var cfg zap.Config
	if development {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.Level = lvl
	return cfg.Build()
}

// Metrics holds the process-wide Prometheus instruments.
type Metrics struct {
	reg *prometheus.Registry

	FramesSent     prometheus.Counter // tunnel frames sent
	FramesRecv     prometheus.Counter // tunnel frames received
	BytesSent      prometheus.Counter // tunnel payload bytes sent
	BytesRecv      prometheus.Counter // tunnel payload bytes received
	ReqForwarded   prometheus.Counter // SNMP requests forwarded
	ReqErrors      prometheus.Counter // forwarding errors (timeout, dial, parse)
	NotifsRelayed  prometheus.Counter // traps/informs relayed
	NotifsFiltered prometheus.Counter // notifications dropped by the configured filter
	DropTotal      prometheus.Counter // dropped datagrams/frames (all causes)
	Reconnects     prometheus.Counter // tunnel reconnects
	ACLDenied      prometheus.Counter // front-leg clients refused by the allow-list
	WritesDenied   prometheus.Counter // SET requests refused by the write policy
	RateLimited    prometheus.Counter // front-leg requests refused by the rate limit
	SessionsDenied prometheus.Counter // (D)TLS sessions refused by the session cap
	TunnelUp       prometheus.Gauge   // 1 when the tunnel session is up
	SessionsActive prometheus.Gauge   // (D)TLS sessions currently holding a cap slot
	ForwardLatency prometheus.Histogram
}

// NewMetrics registers a fresh metric set on a new registry.
func NewMetrics() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}
	m.FramesSent = mustCounter(m.reg, "snmp_shield_tunnel_frames_sent_total", "Tunnel frames sent.")
	m.FramesRecv = mustCounter(m.reg, "snmp_shield_tunnel_frames_received_total", "Tunnel frames received.")
	m.BytesSent = mustCounter(m.reg, "snmp_shield_tunnel_bytes_sent_total", "Tunnel payload bytes sent.")
	m.BytesRecv = mustCounter(m.reg, "snmp_shield_tunnel_bytes_received_total", "Tunnel payload bytes received.")
	m.ReqForwarded = mustCounter(m.reg, "snmp_shield_requests_forwarded_total", "SNMP requests forwarded end to end.")
	m.ReqErrors = mustCounter(m.reg, "snmp_shield_request_errors_total", "SNMP request forwarding errors.")
	m.NotifsRelayed = mustCounter(m.reg, "snmp_shield_notifications_relayed_total", "Traps/informs relayed.")
	m.NotifsFiltered = mustCounter(m.reg, "snmp_shield_notifications_filtered_total", "Notifications dropped by the configured filter.")
	m.DropTotal = mustCounter(m.reg, "snmp_shield_drops_total", "Datagrams or frames dropped.")
	m.Reconnects = mustCounter(m.reg, "snmp_shield_tunnel_reconnects_total", "Tunnel reconnections.")
	m.ACLDenied = mustCounter(m.reg, "snmp_shield_acl_denied_total", "Front-leg requests refused by the client allow-list.")
	m.WritesDenied = mustCounter(m.reg, "snmp_shield_writes_denied_total", "SET requests refused by the write policy.")
	m.RateLimited = mustCounter(m.reg, "snmp_shield_rate_limited_total", "Front-leg requests refused by the per-client rate limit.")
	m.SessionsDenied = mustCounter(m.reg, "snmp_shield_sessions_denied_total", "Inbound (D)TLS sessions refused by the session cap.")
	m.TunnelUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "snmp_shield_tunnel_up",
		Help: "1 when the tunnel session is established.",
	})
	m.reg.MustRegister(m.TunnelUp)
	// Occupancy of the session-cap semaphore. Denials alone say nothing about
	// how close a box is to its ceiling, and the cap is the one resource an
	// unauthenticated peer can consume: a slot held by a vanished client is
	// invisible without this gauge.
	m.SessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "snmp_shield_sessions_active",
		Help: "Concurrent (D)TLS sessions currently holding a session-cap slot.",
	})
	m.reg.MustRegister(m.SessionsActive)
	m.ForwardLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "snmp_shield_forward_latency_seconds",
		Help:    "End-to-end request forwarding latency.",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
	})
	m.reg.MustRegister(m.ForwardLatency)
	return m
}

func mustCounter(reg *prometheus.Registry, name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	reg.MustRegister(c)
	return c
}

// Handler returns the Prometheus scrape handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// CounterList returns the counters in the fixed SNMP MIB row order
// (.20.1..n): frames sent/received, bytes sent/received, requests
// forwarded/errors, notifications relayed/filtered, drops, reconnects,
// then the access-policy counters (ACL denied, writes denied, rate
// limited) and the session-cap counter. The order is a compatibility
// contract for the SNMP metrics MIB — append only, never reorder.
func (m *Metrics) CounterList() []prometheus.Counter {
	return []prometheus.Counter{
		m.FramesSent, m.FramesRecv, m.BytesSent, m.BytesRecv,
		m.ReqForwarded, m.ReqErrors, m.NotifsRelayed, m.NotifsFiltered,
		m.DropTotal, m.Reconnects,
		m.ACLDenied, m.WritesDenied, m.RateLimited,
		m.SessionsDenied,
	}
}

// ServeMetrics serves /metrics on addr until the process exits. It is
// intended to run in its own goroutine.
func ServeMetrics(addr string, handler http.Handler, log *zap.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server", zap.Error(err))
		}
	}()
	return srv
}

// ShutdownMetrics gracefully stops the metrics server.
func ShutdownMetrics(srv *http.Server) {
	if srv == nil {
		return
	}
	_ = srv.Close()
	_ = os.Stdout.Sync()
}
