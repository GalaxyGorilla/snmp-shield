package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// A pysnmp v3 agent, independent of net-snmp.
//
// The v3 agent leg is the one place where the proxy is a command generator
// against somebody else's engine: RFC 3414 discovery, key localization to
// that engine, signing, encryption and parsing their answer. The host
// snmpd (5.6.2.1) and the container snmpd (5.9.3) are both net-snmp, so a
// bug in that leg could survive both. This fixture runs pysnmp's USM engine
// and BER codec instead; the responder code is tiny and read-only, but the
// wire stack is a separate implementation.
//
// It is a process fixture, never a service: loopback only, random port,
// killed at cleanup. A missing venv/module is an environment skip (a
// failure under `make conformance-required`), matching the other peers.

type pysnmpV3Agent struct {
	addr string
	cmd  *exec.Cmd
	log  *lockedBuffer
	done chan struct{}
	once sync.Once
}

func (a *pysnmpV3Agent) Addr() string { return a.addr }

func (a *pysnmpV3Agent) Stop(t *testing.T) {
	t.Helper()
	a.once.Do(func() {
		_ = a.cmd.Process.Kill()
		<-a.done
	})
	if t.Failed() {
		t.Logf("pysnmp v3 agent output:\n%s", a.log.String())
	}
}

// requirePysnmpV3Agent returns the venv interpreter and fixture script, or
// skips with a reason naming the fix.
func requirePysnmpV3Agent(t *testing.T) (python, script string) {
	t.Helper()
	python = filepath.Join(peersDir(), ".venv", "bin", "python")
	script = filepath.Join(peersDir(), "v3_agent.py")
	if _, err := os.Stat(python); err != nil {
		skipOrFail(t, "python venv missing (%s) — run `make peers`", python)
	}
	if out, err := exec.Command(python, "-c", "import pysnmp").CombinedOutput(); err != nil {
		skipOrFail(t, "pysnmp missing in the venv (%s) — run `make peers`", firstLine(string(out)))
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("conformance: pysnmp agent fixture missing: %v", err)
	}
	return python, script
}

// startPysnmpV3Agent launches the pysnmp agent and waits for a direct v3
// GET before returning, so a broken fixture never looks like a proxy bug.
func startPysnmpV3Agent(t *testing.T) v3AgentFixture {
	t.Helper()
	python, script := requirePysnmpV3Agent(t)

	addr := testkit.FreeUDPPort(t, "127.0.0.1")
	cmd := exec.Command(python, script,
		"--endpoint", addr,
		"--user", mgwUser,
		"--auth-key", authPass,
		"--auth-proto", "SHA",
		"--priv-key", privPass,
		"--priv-proto", "AES",
	)
	lb := &lockedBuffer{}
	cmd.Stdout = lb
	cmd.Stderr = lb
	if err := cmd.Start(); err != nil {
		skipOrFail(t, "pysnmp v3 agent cannot start: %v", err)
	}
	agent := &pysnmpV3Agent{addr: addr, cmd: cmd, log: lb, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(agent.done)
	}()
	t.Cleanup(func() { agent.Stop(t) })

	waitV3Agent(t, addr)
	return agent
}
