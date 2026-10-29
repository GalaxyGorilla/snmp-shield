package observ

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// This package is small but it is the one an operator touches first: the
// logger decides whether a failure is visible, and the metrics endpoint is
// the only Prometheus surface. It used to have no tests at all, so a broken
// handler, an unregistered instrument or a shutdown that leaves the port
// behind would all show up in production rather than here.

func TestLogLevels(t *testing.T) {
	for _, tc := range []struct {
		level       string
		development bool
	}{
		{"debug", false},
		{"info", false},
		{"error", false},
		{"debug", true},
		{"info", true},
	} {
		log, err := Log(tc.level, tc.development)
		if err != nil {
			t.Fatalf("Log(%q, %v): %v", tc.level, tc.development, err)
		}
		if log == nil {
			t.Fatalf("Log(%q, %v) returned a nil logger", tc.level, tc.development)
		}
	}

	// An unknown level is a startup error, not a silent fallback to info.
	if _, err := Log("verbose", false); err == nil {
		t.Fatal("Log accepted an unknown level")
	} else if !strings.Contains(err.Error(), `log level "verbose"`) {
		t.Fatalf("error does not name the level: %v", err)
	}

	// An empty level is INFO in zap's own vocabulary, so this is documented
	// behaviour rather than an error: config.Defaults() always fills it in,
	// and a caller that passes "" gets the safe default, not debug.
	log, err := Log("", false)
	if err != nil {
		t.Fatalf("Log(\"\"): %v", err)
	}
	if !log.Core().Enabled(zap.InfoLevel) || log.Core().Enabled(zap.DebugLevel) {
		t.Fatal(`Log("") is not the info default`)
	}
}

// TestLogHonoursLevel checks the level through the real logger, using its
// own core rather than a synthetic one: a production deployment that asks
// for debug and silently gets info (or the reverse) is a support problem.
func TestLogHonoursLevel(t *testing.T) {
	log, err := Log("error", false)
	if err != nil {
		t.Fatal(err)
	}
	if log.Core().Enabled(zap.InfoLevel) {
		t.Fatal("Log(\"error\") has info enabled")
	}
	if !log.Core().Enabled(zap.ErrorLevel) {
		t.Fatal("Log(\"error\") does not have error enabled")
	}

	log, err = Log("debug", true)
	if err != nil {
		t.Fatal(err)
	}
	if !log.Core().Enabled(zap.DebugLevel) {
		t.Fatal("Log(\"debug\") does not have debug enabled")
	}
}

// TestMetricsScrape covers NewMetrics + Handler as one unit, because the
// failure that matters is "the instrument exists but is not on the scrape
// page": the registry is private, so only the handler proves registration.
func TestMetricsScrape(t *testing.T) {
	met := NewMetrics()
	met.ReqForwarded.Inc()
	met.TunnelUp.Set(1)
	met.ForwardLatency.Observe(0.01)

	rec := scrape(t, met.Handler())
	for _, want := range []string{
		`snmp_shield_requests_forwarded_total 1`,
		`snmp_shield_tunnel_up 1`,
		`snmp_shield_sessions_active 0`,
		`snmp_shield_forward_latency_seconds_count 1`,
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("scrape output is missing %q", want)
		}
	}
}

// TestCounterListOrder pins the SNMP MIB row order. `snmpmetrics` renders
// CounterList() as <base>.20.<n>, so appending in the middle silently
// repoints an operator's existing rows (and their thresholds) at a
// different counter. Append only.
func TestCounterListOrder(t *testing.T) {
	met := NewMetrics()
	want := []string{
		"frames_sent",
		"frames_received",
		"bytes_sent",
		"bytes_received",
		"requests_forwarded",
		"request_errors",
		"notifications_relayed",
		"notifications_filtered",
		"drops",
		"tunnel_reconnects",
		"acl_denied",
		"writes_denied",
		"rate_limited",
		"sessions_denied",
	}
	got := met.CounterList()
	if len(got) != len(want) {
		t.Fatalf("CounterList has %d counters, want %d (append only, never reorder)", len(got), len(want))
	}
	for i, c := range got {
		desc := c.Desc().String()
		if !strings.Contains(desc, want[i]) {
			t.Errorf("counter row %d = %s, want a counter named %q — this is the SNMP MIB row order",
				i+1, desc, want[i])
		}
	}
}

// TestServeMetricsAndShutdown drives the real listener: it must serve
// /metrics, refuse other paths, and release the port on shutdown. A
// ServeMetrics that never closes would keep a restart from binding.
func TestServeMetricsAndShutdown(t *testing.T) {
	addr := freeTCPAddr(t)
	srv := ServeMetrics(addr, NewMetrics().Handler(), zap.NewNop())

	body := get(t, "http://"+addr+"/metrics", 5*time.Second)
	if !strings.Contains(body, "snmp_shield_tunnel_up") {
		t.Fatalf("/metrics body does not look like a scrape: %.120q", body)
	}

	resp, err := http.Get("http://" + addr + "/nope")
	if err != nil {
		t.Fatalf("GET /nope: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404 (only /metrics is exposed)", resp.StatusCode)
	}

	ShutdownMetrics(srv)

	// The port must become usable again. Poll rather than sleep once: Close
	// is synchronous for the listener but the goroutine may still be in
	// ListenAndServe's return path.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics port was not released after shutdown: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServeMetricsBindErrorIsLogged pins the other half of ServeMetrics:
// a port already in use must be reported, never swallowed. It returns
// before the goroutine runs, so the log is what a startup problem shows.
func TestServeMetricsBindErrorIsLogged(t *testing.T) {
	addr := freeTCPAddr(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("reserve %s: %v", addr, err)
	}
	defer ln.Close()

	core, logs := observer.New(zap.ErrorLevel)
	_ = ServeMetrics(addr, NewMetrics().Handler(), zap.New(core))

	deadline := time.Now().Add(5 * time.Second)
	for logs.FilterMessage("metrics server").Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a metrics listener that cannot bind was not logged at error level")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if entries := logs.FilterMessage("metrics server").All(); !strings.Contains(fmt.Sprint(entries[0].ContextMap()["error"]), "in use") {
		t.Fatalf("bind error was logged without the cause: %v", entries[0].ContextMap())
	}
}

// TestShutdownMetricsNil covers the "metrics disabled" path: Run defers
// ShutdownMetrics unconditionally.
func TestShutdownMetricsNil(t *testing.T) {
	ShutdownMetrics(nil)
}

// --- helpers -------------------------------------------------------------------

// freeTCPAddr reserves a loopback TCP port and releases it.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release tcp port: %v", err)
	}
	return addr
}

// scrape runs the handler once and returns the body.
func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scrape listener: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	return get(t, "http://"+ln.Addr().String()+"/metrics", 5*time.Second)
}

// get retries until the server answers or the deadline passes, so a cold
// listener never turns into a flake.
func get(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr != nil {
				t.Fatalf("read %s: %v", url, rerr)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d", url, resp.StatusCode)
			}
			return string(body)
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("GET %s never answered: %v", url, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
