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
	dto "github.com/prometheus/client_model/go"
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
//
// Process-level instruments (tunnel frames/bytes/reconnects and the
// session gauges) are unlabelled. Request, notification and access
// counters are per-agent: the public fields are the process aggregate
// used by the SNMP MIB, and ForAgent returns a view that updates both the
// aggregate and an `agent`-labelled Prometheus series.
type Metrics struct {
	reg *prometheus.Registry

	// Process-level instruments (unlabelled).
	FramesSent     prometheus.Counter // tunnel frames sent
	FramesRecv     prometheus.Counter // tunnel frames received
	BytesSent      prometheus.Counter // tunnel payload bytes sent
	BytesRecv      prometheus.Counter // tunnel payload bytes received
	Reconnects     prometheus.Counter // tunnel reconnects
	SessionsDenied prometheus.Counter // (D)TLS sessions refused by the session cap
	TunnelUp       prometheus.Gauge   // 1 when the tunnel session is up
	SessionsActive prometheus.Gauge   // (D)TLS sessions currently holding a cap slot

	// Per-agent instruments. These are the aggregate counters for the
	// SNMP MIB; use ForAgent for the labelled Prometheus view.
	ReqForwarded   prometheus.Counter // SNMP requests forwarded
	ReqErrors      prometheus.Counter // forwarding errors (timeout, dial, parse)
	NotifsRelayed  prometheus.Counter // traps/informs relayed
	NotifsFiltered prometheus.Counter // notifications dropped by the configured filter
	DropTotal      prometheus.Counter // dropped datagrams/frames (all causes)
	ACLDenied      prometheus.Counter // front-leg clients refused by the allow-list
	WritesDenied   prometheus.Counter // SET requests refused by the write policy
	RateLimited    prometheus.Counter // front-leg requests refused by the rate limit
	ForwardLatency prometheus.Histogram

	reqForwardedVec   *prometheus.CounterVec
	reqErrorsVec      *prometheus.CounterVec
	notifsRelayedVec  *prometheus.CounterVec
	notifsFilteredVec *prometheus.CounterVec
	dropTotalVec      *prometheus.CounterVec
	aclDeniedVec      *prometheus.CounterVec
	writesDeniedVec   *prometheus.CounterVec
	rateLimitedVec    *prometheus.CounterVec
	forwardLatencyVec *prometheus.HistogramVec
}

// NewMetrics registers a fresh metric set on a new registry.
func NewMetrics() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}
	m.FramesSent = mustCounter(m.reg, "snmp_shield_tunnel_frames_sent_total", "Tunnel frames sent.")
	m.FramesRecv = mustCounter(m.reg, "snmp_shield_tunnel_frames_received_total", "Tunnel frames received.")
	m.BytesSent = mustCounter(m.reg, "snmp_shield_tunnel_bytes_sent_total", "Tunnel payload bytes sent.")
	m.BytesRecv = mustCounter(m.reg, "snmp_shield_tunnel_bytes_received_total", "Tunnel payload bytes received.")
	m.Reconnects = mustCounter(m.reg, "snmp_shield_tunnel_reconnects_total", "Tunnel reconnections.")
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

	m.ReqForwarded = newCounter("snmp_shield_requests_forwarded_total", "SNMP requests forwarded end to end.")
	m.reqForwardedVec = mustCounterVec(m.reg, "snmp_shield_requests_forwarded_total", "SNMP requests forwarded end to end.")
	m.ReqErrors = newCounter("snmp_shield_request_errors_total", "SNMP request forwarding errors.")
	m.reqErrorsVec = mustCounterVec(m.reg, "snmp_shield_request_errors_total", "SNMP request forwarding errors.")
	m.NotifsRelayed = newCounter("snmp_shield_notifications_relayed_total", "Traps/informs relayed.")
	m.notifsRelayedVec = mustCounterVec(m.reg, "snmp_shield_notifications_relayed_total", "Traps/informs relayed.")
	m.NotifsFiltered = newCounter("snmp_shield_notifications_filtered_total", "Notifications dropped by the configured filter.")
	m.notifsFilteredVec = mustCounterVec(m.reg, "snmp_shield_notifications_filtered_total", "Notifications dropped by the configured filter.")
	m.DropTotal = newCounter("snmp_shield_drops_total", "Datagrams or frames dropped.")
	m.dropTotalVec = mustCounterVec(m.reg, "snmp_shield_drops_total", "Datagrams or frames dropped.")
	m.ACLDenied = newCounter("snmp_shield_acl_denied_total", "Front-leg requests refused by the client allow-list.")
	m.aclDeniedVec = mustCounterVec(m.reg, "snmp_shield_acl_denied_total", "Front-leg requests refused by the client allow-list.")
	m.WritesDenied = newCounter("snmp_shield_writes_denied_total", "SET requests refused by the write policy.")
	m.writesDeniedVec = mustCounterVec(m.reg, "snmp_shield_writes_denied_total", "SET requests refused by the write policy.")
	m.RateLimited = newCounter("snmp_shield_rate_limited_total", "Front-leg requests refused by the per-client rate limit.")
	m.rateLimitedVec = mustCounterVec(m.reg, "snmp_shield_rate_limited_total", "Front-leg requests refused by the per-client rate limit.")
	m.ForwardLatency = newHistogram("snmp_shield_forward_latency_seconds", "End-to-end request forwarding latency.")
	m.forwardLatencyVec = mustHistogramVec(m.reg, "snmp_shield_forward_latency_seconds", "End-to-end request forwarding latency.")
	return m
}

// ForAgent returns a metrics view whose per-agent instruments update both
// the process aggregate (SNMP MIB) and the `agent`-labelled Prometheus
// series. Process-level instruments are shared unchanged.
func (m *Metrics) ForAgent(agent string) *Metrics {
	if m == nil || m.reqForwardedVec == nil {
		return m
	}
	v := *m
	v.ReqForwarded = dualCounter{m.ReqForwarded, m.reqForwardedVec.WithLabelValues(agent)}
	v.ReqErrors = dualCounter{m.ReqErrors, m.reqErrorsVec.WithLabelValues(agent)}
	v.NotifsRelayed = dualCounter{m.NotifsRelayed, m.notifsRelayedVec.WithLabelValues(agent)}
	v.NotifsFiltered = dualCounter{m.NotifsFiltered, m.notifsFilteredVec.WithLabelValues(agent)}
	v.DropTotal = dualCounter{m.DropTotal, m.dropTotalVec.WithLabelValues(agent)}
	v.ACLDenied = dualCounter{m.ACLDenied, m.aclDeniedVec.WithLabelValues(agent)}
	v.WritesDenied = dualCounter{m.WritesDenied, m.writesDeniedVec.WithLabelValues(agent)}
	v.RateLimited = dualCounter{m.RateLimited, m.rateLimitedVec.WithLabelValues(agent)}
	v.ForwardLatency = dualHistogram{m.ForwardLatency, m.forwardLatencyVec.WithLabelValues(agent)}
	return &v
}

func mustCounter(reg *prometheus.Registry, name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	reg.MustRegister(c)
	return c
}

func newCounter(name, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
}

func newHistogram(name, help string) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
	})
}

func mustCounterVec(reg *prometheus.Registry, name, help string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, []string{"agent"})
	reg.MustRegister(c)
	return c
}

func mustHistogramVec(reg *prometheus.Registry, name, help string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
	}, []string{"agent"})
	reg.MustRegister(h)
	return h
}

// dualCounter updates the process aggregate and the per-agent series.
type dualCounter struct {
	agg   prometheus.Counter
	child prometheus.Counter
}

func (d dualCounter) Inc()                   { d.agg.Inc(); d.child.Inc() }
func (d dualCounter) Add(v float64)          { d.agg.Add(v); d.child.Add(v) }
func (d dualCounter) Desc() *prometheus.Desc { return d.child.Desc() }
func (d dualCounter) Write(m *dto.Metric) error {
	return d.child.Write(m)
}
func (d dualCounter) Describe(ch chan<- *prometheus.Desc) { d.child.Describe(ch) }
func (d dualCounter) Collect(ch chan<- prometheus.Metric) { d.child.Collect(ch) }

// dualHistogram updates the process aggregate and the per-agent series.
// HistogramVec.WithLabelValues returns an Observer, not a Histogram, so
// the Metric/Collector methods delegate to the aggregate; the labelled
// series is registered by the vector and updated by Observe.
type dualHistogram struct {
	agg   prometheus.Histogram
	child prometheus.Observer
}

func (d dualHistogram) Observe(v float64)      { d.agg.Observe(v); d.child.Observe(v) }
func (d dualHistogram) Desc() *prometheus.Desc { return d.agg.Desc() }
func (d dualHistogram) Write(m *dto.Metric) error {
	return d.agg.Write(m)
}
func (d dualHistogram) Describe(ch chan<- *prometheus.Desc) { d.agg.Describe(ch) }
func (d dualHistogram) Collect(ch chan<- prometheus.Metric) { d.agg.Collect(ch) }

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
