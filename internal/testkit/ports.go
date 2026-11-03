package testkit

import (
	"net"
	"sync"
	"testing"
	"time"
)

// usedPorts remembers every port handed out in this process. A probe closes
// its socket, so the kernel is free to return the same ephemeral port to the
// next probe — including a probe for a different host form ([::] vs
// 127.0.0.1). Two fixtures in one test then bind the same port and one dies
// with "address already in use". Keying on the port (not the host) closes
// that gap; the set is process-lifetime because a test process uses orders of
// magnitude fewer than 64K ports.
var (
	usedPortsMu sync.Mutex
	usedPorts   = make(map[string]struct{})
)

// FreeUDPPort returns a loopback UDP address that was free a moment ago and
// has not been handed out before in this process.
//
// Prefer binding "127.0.0.1:0" and reading LocalAddr(); this exists for
// configurations that must name an address *before* anything listens (for
// example a manager's listen_addr, which the proxy binds itself). The port
// can still be taken between the probe and the bind, so callers that can
// must retry or use WaitUDPBound.
func FreeUDPPort(t testing.TB, host string) string {
	t.Helper()
	if host == "" {
		host = "127.0.0.1"
	}
	for attempt := 0; attempt < 100; attempt++ {
		conn, err := net.ListenPacket("udp", host+":0")
		if err != nil {
			t.Fatalf("testkit: probe free udp port: %v", err)
		}
		addr := conn.LocalAddr().String()
		if err := conn.Close(); err != nil {
			t.Fatalf("testkit: close probe socket: %v", err)
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("testkit: probe address %q: %v", addr, err)
		}
		usedPortsMu.Lock()
		_, seen := usedPorts[port]
		if !seen {
			usedPorts[port] = struct{}{}
		}
		usedPortsMu.Unlock()
		if !seen {
			return addr
		}
	}
	t.Fatalf("testkit: no unused UDP port after 100 probes on %s", host)
	return ""
}

// UDPBound reports whether something is bound on addr right now. It is the
// non-fatal half of WaitUDPBound, for callers that want to decide what a
// missing listener means (for example: fail fast because the process they
// started has already exited).
//
// It is a loopback/liveness probe, not a proof of a listener: a UDP "dial" to
// an address with no route reports success, so a non-local address looks
// bound (there is no connect handshake to fail). For a local address the
// kernel's ICMP port-unreachable does the work.
func UDPBound(addr string) bool {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x00}); err != nil {
		return false
	}
	// A write to a closed UDP port surfaces on the *next* operation.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, rerr := conn.Read(buf)
	var nerr net.Error
	if rerr != nil && !(asTimeout(rerr, &nerr) && nerr.Timeout()) {
		return false // ECONNREFUSED (or similar): nothing is bound yet
	}
	return true
}

// WaitUDPBound blocks until something answers on addr (or the deadline
// passes).
//
// A UDP "dial" cannot prove a listener exists, so readiness is probed by
// sending an empty datagram and asking whether the kernel reported
// ECONNREFUSED. That is cheap and does not disturb a proxy: an empty
// datagram is dropped by every handler by design.
func WaitUDPBound(t testing.TB, addr string, timeout time.Duration) {
	t.Helper()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if UDPBound(addr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("testkit: %s not bound within %s", addr, timeout)
}

func asTimeout(err error, out *net.Error) bool {
	if ne, ok := err.(net.Error); ok {
		*out = ne
		return ne.Timeout()
	}
	return false
}
