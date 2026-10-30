package conformance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// lifecycle_test.go — the SIGNAL edge of the process, which no in-process
// test can reach.
//
// `internal/proxy` covers everything from the SIGHUP handler inwards
// (reloadLoop → reloadConfig → config.Load → the next datagram), but the
// handler registration, the fact that SIGHUP does not stop the process, and
// that SIGTERM/SIGINT exit 0 are only observable on a real process. That is
// the operator's actual interface (`systemctl reload` / `systemctl restart`),
// so it is driven here with the built binary, like the vendor matrix.
//
// The tests are deliberately vendor-free: no peer, no Docker, no skip. They
// run in every `make conformance`, and are the reason a bare host's green run
// says something about shutdown.

// TestProcessSIGHUPReloadsAccessPolicy is the incident workflow end to end:
// the service is serving, an operator edits access.read_only and reloads,
// and the next SET is refused without a restart.
func TestProcessSIGHUPReloadsAccessPolicy(t *testing.T) {
	device := newDevice(t, testkit.AgentOptions{Community: community})
	front := testkit.FreeUDPPort(t, "")
	cfgPath := filepath.Join(t.TempDir(), "gateway.yaml")
	writeGatewayYAML(t, cfgPath, front, device.Addr(), false)

	proc := startProxy(t, "usm-gateway-config", "gateway", "--config", cfgPath)
	proc.waitFront(t, front)

	g := newSession(t, front, "3", 2*time.Second)
	if err := g.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = g.Conn.Close() }()
	if _, err := g.Get([]string{sysDescr}); err != nil {
		t.Fatalf("GET before reload: %v", err)
	}
	if res, err := g.Set([]gosnmp.SnmpPDU{{
		Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "renamed",
	}}); err != nil || res.Error != gosnmp.NoError {
		t.Fatalf("SET before reload: err=%v status=%v", err, res.Error)
	}
	if n := device.SETs(); n != 1 {
		t.Fatalf("the allowed SET reached the device %d time(s), want 1", n)
	}

	// Operator locks writes and reloads.
	writeGatewayYAML(t, cfgPath, front, device.Addr(), true)
	proc.signal(t, syscall.SIGHUP)

	// The signal is asynchronous, so poll the property rather than sleeping:
	// after the reload every SET must be refused with an answer.
	deadline := time.Now().Add(10 * time.Second)
	var lastStatus gosnmp.SNMPError
	for {
		res, err := g.Set([]gosnmp.SnmpPDU{{
			Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "renamed",
		}})
		if err != nil {
			t.Fatalf("SET after reload: %v", err)
		}
		lastStatus = res.Error
		if res.Error == gosnmp.NotWritable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP did not install the read-only policy (last status %v)", lastStatus)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A SET already in flight when the signal landed is legitimately allowed
	// (the reload is asynchronous), so the baseline is taken once the policy
	// is visibly in force — not before the signal.
	settled := device.SETs()
	if res, err := g.Set([]gosnmp.SnmpPDU{{
		Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "renamed",
	}}); err != nil || res.Error != gosnmp.NotWritable {
		t.Fatalf("SET under the reloaded policy: err=%v status=%v, want notWritable", err, res.Error)
	}
	if n := device.SETs(); n != settled {
		t.Fatalf("a refused SET reached the device (sets=%d, want %d)", n, settled)
	}
	// Read-only is a write lock, not an outage.
	if _, err := g.Get([]string{sysDescr}); err != nil {
		t.Fatalf("GET under the reloaded read-only policy: %v", err)
	}

	// SIGTERM is what systemd sends; the process must exit 0 on its own.
	proc.signal(t, syscall.SIGTERM)
	if code := proc.waitExit(t, 10*time.Second); code != 0 {
		t.Fatalf("exit code after SIGTERM = %d, want 0; output:\n%s", code, proc.log.String())
	}
}

// TestProcessSIGHUPIsNotShutdown pins the trap the reload code comments
// warn about: SIGHUP must not be on the shutdown context. A regression there
// looks like "systemctl reload killed the proxy" — a full outage from an
// operator action that is supposed to be safe.
func TestProcessSIGHUPIsNotShutdown(t *testing.T) {
	device := newDevice(t, testkit.AgentOptions{Community: community})
	front := testkit.FreeUDPPort(t, "")
	// Flags mode: no --config, so a reload is a logged no-op. The point is
	// that it is a no-op and not an exit.
	proc := startProxy(t, "usm-gateway-flags", "gateway",
		"--security", "usm-gateway",
		"--listen", front, "--agent", device.Addr(), "--community", community,
		"--auth-pass", authPass, "--priv-pass", privPass)
	proc.waitFront(t, front)

	g := newSession(t, front, "3", 2*time.Second)
	if err := g.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = g.Conn.Close() }()
	if _, err := g.Get([]string{sysDescr}); err != nil {
		t.Fatalf("GET before SIGHUP: %v", err)
	}

	proc.signal(t, syscall.SIGHUP)

	// It must still answer afterwards, and it must still be alive.
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-proc.done:
			t.Fatalf("SIGHUP terminated the proxy; output:\n%s", proc.log.String())
		default:
		}
		if _, err := g.Get([]string{sysDescr}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy stopped answering after SIGHUP; output:\n%s", proc.log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if log := proc.log.String(); !contains(log, "SIGHUP ignored") {
		t.Fatalf("flags-mode SIGHUP was not reported as ignored; output:\n%s", log)
	}

	// SIGINT is the interactive equivalent of systemd's SIGTERM.
	proc.signal(t, os.Interrupt)
	if code := proc.waitExit(t, 10*time.Second); code != 0 {
		t.Fatalf("exit code after SIGINT = %d, want 0; output:\n%s", code, proc.log.String())
	}
}

// TestProcessShutdownUnderLoad pins the half of shutdown the in-process tests
// cannot see: a signal that arrives while a request is in flight must still
// end the process promptly and cleanly.
//
// The risk this guards is a shutdown that waits for outstanding work: every
// translator holds a 15s pending timer per forwarded request, so a process
// that joined its goroutines instead of cancelling them would take 15s (or
// hang) to stop — and systemd would eventually SIGKILL it mid-write. The
// device is slow on purpose, so the request is still pending when the signal
// lands.
func TestProcessShutdownUnderLoad(t *testing.T) {
	device := newDevice(t, testkit.AgentOptions{Community: community, Delay: 400 * time.Millisecond})
	front := testkit.FreeUDPPort(t, "")
	proc := startProxy(t, "usm-gateway-under-load", "gateway",
		"--security", "usm-gateway",
		"--listen", front, "--agent", device.Addr(), "--community", community,
		"--auth-pass", authPass, "--priv-pass", privPass)
	proc.waitFront(t, front)

	// Warm up, so the slow request below is not the first one (the first
	// also triggers engine discovery).
	warm := newSession(t, front, "3", 3*time.Second)
	if err := warm.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := warm.Get([]string{sysDescr}); err != nil {
		t.Fatalf("warmup GET: %v", err)
	}
	_ = warm.Conn.Close()

	// A short client timeout: the request is expected to go unanswered once
	// the proxy is gone, and the test should not spend 5s proving that.
	g := newSession(t, front, "3", 2*time.Second)
	if err := g.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = g.Conn.Close() }()

	inflight := make(chan error, 1)
	go func() {
		_, err := g.Get([]string{sysDescr})
		inflight <- err
	}()
	// Let the request reach the device (it holds it for 400ms) before the
	// signal, so "in flight" is not a guess.
	time.Sleep(100 * time.Millisecond)

	proc.signal(t, syscall.SIGTERM)
	code := proc.waitExit(t, 10*time.Second)
	if code != 0 {
		t.Fatalf("exit code after SIGTERM with a request in flight = %d, want 0; output:\n%s",
			code, proc.log.String())
	}
	// The client may get the answer or a timeout — both are honest outcomes
	// for a proxy that was told to stop. What must not happen is a hang.
	select {
	case <-inflight:
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight request never returned after the proxy exited")
	}
	if log := proc.log.String(); contains(log, "panic") {
		t.Fatalf("shutdown panicked; output:\n%s", log)
	}
}

// TestProcessBindFailureIsLoud pins the startup contract a service manager
// depends on: if the front leg cannot bind, the process must exit non-zero
// with the cause in its log — never exit 0, and never sit there serving
// nothing while the unit looks healthy. TEST-NET-1 (192.0.2.0/24) is used
// because it can never be assigned to a local interface on any platform,
// unlike "port already in use", which macOS and Linux treat differently for
// UDP (SO_REUSEADDR lets a second bind through on macOS).
func TestProcessBindFailureIsLoud(t *testing.T) {
	device := newDevice(t, testkit.AgentOptions{Community: community})
	proc := startProxy(t, "usm-gateway-badbind", "gateway",
		"--security", "usm-gateway",
		"--listen", "192.0.2.1:16161", "--agent", device.Addr(),
		"--community", community, "--auth-pass", authPass, "--priv-pass", privPass)

	code := proc.waitExit(t, 15*time.Second)
	if code == 0 {
		t.Fatalf("a front leg that cannot bind exited 0; output:\n%s", proc.log.String())
	}
	log := proc.log.String()
	if !contains(log, "proxy exited") || !contains(log, "16161") {
		t.Fatalf("the bind failure was not logged with its cause; output:\n%s", log)
	}
}

// TestAwaitFrontFailsFastWhenTheProcessExited pins the harness diagnostic
// that makes a lost port race readable. `FreeUDPPort` is a probe, not a
// reservation, so a probed port can be taken between the probe and the bind;
// without this, the test waits out the whole timeout and reports a message
// that reads like a proxy defect.
//
// The proc is built by hand rather than started: the property is "a dead
// process is noticed immediately", and a real unbindable address is not
// usable here (a UDP dial to a non-local address reports "bound", because
// UDP has no connect handshake to fail).
func TestAwaitFrontFailsFastWhenTheProcessExited(t *testing.T) {
	done := make(chan struct{})
	close(done)
	p := &proxyProc{name: "gone", done: done, waitErr: errors.New("exit status 1")}

	start := time.Now()
	err := p.awaitFront("127.0.0.1:1", 10*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("awaitFront reported success for a process that already exited")
	}
	if !contains(err.Error(), "exited before binding") {
		t.Fatalf("error = %q, want the exit named as the cause", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("awaitFront took %s to notice the exit", elapsed)
	}
}

// writeGatewayYAML writes a complete usm-gateway config. readOnly toggles the
// access block, which is the only reloadable part.
func writeGatewayYAML(t *testing.T, path, listen, agent string, readOnly bool) {
	t.Helper()
	access := ""
	if readOnly {
		access = "access:\n  read_only: true\n"
	}
	body := fmt.Sprintf(`role: gateway
gateway:
  listen_addr: %q
  agent_addr: %q
  agent_community: %q
security:
  mode: usm-gateway
  engine_store: %q
  users:
    - name: %s
      auth_protocol: sha
      auth_passphrase: %q
      priv_protocol: aes
      priv_passphrase: %q
%s`, listen, agent, community,
		filepath.Join(filepath.Dir(path), "engine.json"),
		gatewayUsr, authPass, privPass, access)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
