package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// binaryPath is the proxy built once per test run. The conformance matrix
// drives the real CLI, not an in-process runner: that also covers flag
// parsing, defaults and validation, which an internal harness would bypass.
var binaryPath string

// Credentials and community used by the flags-mode fixtures. They are
// constants because every peer must be configured identically; a typo in one
// scenario would otherwise look like a vendor disagreement.
const (
	authPass   = "authpass1"
	privPass   = "privpass1"
	gatewayUsr = "proxy" // usm-gateway flags mode names its user "proxy"
	community  = "public"
	sysDescr   = "1.3.6.1.2.1.1.1.0"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "snmp-shield-conformance")
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance: temp dir: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "snmp-shield")
	cmd := exec.Command(goTool(), "build", "-o", binaryPath, "./cmd/snmp-shield")
	cmd.Dir = repoRoot()
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "conformance: building proxy: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// goTool finds the go command even in a non-login shell where PATH may not
// include the toolchain (a documented trap in this repository).
func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	candidate := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return "go"
}

// --- proxy process ----------------------------------------------------------

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type proxyProc struct {
	name string
	cmd  *exec.Cmd
	log  *lockedBuffer
	done chan struct{}
	once sync.Once
}

// startProxy runs the built binary and registers a clean shutdown. Output is
// attached to the failure report: when a vendor disagrees with us, the proxy
// log is the first thing to read.
func startProxy(t *testing.T, name string, args ...string) *proxyProc {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	lb := &lockedBuffer{}
	cmd.Stdout = lb
	cmd.Stderr = lb
	if err := cmd.Start(); err != nil {
		t.Fatalf("conformance: start %s: %v", name, err)
	}
	p := &proxyProc{name: name, cmd: cmd, log: lb, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { p.Stop(t) })
	return p
}

// Stop shuts the proxy down: SIGINT first (it has a graceful path), SIGKILL
// after a grace period. Idempotent, so a restart test can call it early and
// cleanup can still call it.
func (p *proxyProc) Stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	if t.Failed() {
		t.Logf("%s output:\n%s", p.name, p.log.String())
	}
}

// waitFront blocks until the proxy's UDP front leg is bound.
func waitFront(t *testing.T, addr string) {
	t.Helper()
	testkit.WaitUDPBound(t, addr, 10*time.Second)
}

// --- device ----------------------------------------------------------------

// newDevice starts a fake legacy agent. It records what actually reached the
// device, which is the oracle for "did the proxy forward this?".
func newDevice(t *testing.T, opts testkit.AgentOptions) *testkit.Agent {
	t.Helper()
	return testkit.NewAgent(t, opts)
}

// --- request helpers -------------------------------------------------------

func hostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("conformance: %q is not host:port: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("conformance: bad port in %q: %v", addr, err)
	}
	return host, uint16(port)
}

// newSession is a gosnmp client used by the harness itself (readiness
// probes), never as the peer under test.
func newSession(t *testing.T, target, version string, timeout time.Duration) *gosnmp.GoSNMP {
	t.Helper()
	host, port := hostPort(t, target)
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Transport: "udp",
		Timeout:   timeout,
		Retries:   0,
	}
	switch version {
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 gatewayUsr,
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: authPass,
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        privPass,
		}
	default:
		g.Version = gosnmp.Version2c
		g.Community = community
	}
	return g
}

// waitV2cReady polls until the v2c front leg answers, or fails. A bound UDP
// port proves the listener exists, not that the tunnel behind it works, so
// the two-proxy chain waits for a real answer.
func waitV2cReady(t *testing.T, target string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		g := newSession(t, target, "2c", 400*time.Millisecond)
		if err := g.Connect(); err == nil {
			if _, err = g.Get([]string{sysDescr}); err == nil {
				_ = g.Conn.Close()
				return
			}
			_ = g.Conn.Close()
			last = err
		} else {
			last = err
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("conformance: %s never answered a v2c GET: %v", target, last)
}

// --- assertions ------------------------------------------------------------

func requireOK(t *testing.T, res Result) {
	t.Helper()
	if !res.OK {
		t.Fatalf("expected a successful answer, got error_kind=%q: %s", res.ErrorKind, res.Error)
	}
}

// requireRefused asserts the operation did not succeed AND that it was
// refused in one of the accepted ways. Refuser kind sets differ between
// vendors (net-snmp says "authentication failure", pysnmp says "Wrong
// digest"), so scenarios name the acceptable kinds instead of one.
func requireRefused(t *testing.T, res Result, kinds ...string) {
	t.Helper()
	if res.OK {
		t.Fatalf("expected a refusal, got a successful answer: %v", res.Varbinds)
	}
	for _, k := range kinds {
		if res.ErrorKind == k {
			return
		}
	}
	t.Fatalf("expected refusal kind in %v, got %q: %s", kinds, res.ErrorKind, res.Error)
}

// requireVarbind finds an answer by OID and checks its type and value prefix.
func requireVarbind(t *testing.T, res Result, oid, wantType, wantValueContains string) Varbind {
	t.Helper()
	for _, vb := range res.Varbinds {
		if trimDot(vb.OID) != trimDot(oid) {
			continue
		}
		if wantType != "" && vb.Type != wantType {
			t.Fatalf("%s: type = %q, want %q (varbind %+v)", oid, vb.Type, wantType, vb)
		}
		if wantValueContains != "" && !contains(vb.Value, wantValueContains) {
			t.Fatalf("%s: value = %q, want it to contain %q", oid, vb.Value, wantValueContains)
		}
		return vb
	}
	t.Fatalf("no varbind for %s in %v", oid, res.Varbinds)
	return Varbind{}
}

func trimDot(s string) string {
	for len(s) > 0 && s[0] == '.' {
		s = s[1:]
	}
	return s
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || bytes.Contains([]byte(haystack), []byte(needle))
}

// requireV3Notification checks that a datagram the proxy sent to a trap sink
// is a v3 USM message with authPriv, i.e. the wrapping actually happened.
func requireV3Notification(t *testing.T, dg []byte) *msg.V3Message {
	t.Helper()
	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("notification is not a v3 message: %v", err)
	}
	if m.Header.MsgFlags&0x03 != 0x03 {
		t.Fatalf("notification msgFlags = 0x%02x, want auth+priv", m.Header.MsgFlags)
	}
	if len(m.USM.AuthParams) == 0 || len(m.USM.PrivParams) == 0 {
		t.Fatalf("notification lacks USM auth/priv parameters: %+v", m.USM)
	}
	if m.USM.UserName != gatewayUsr {
		t.Fatalf("notification user = %q, want %q", m.USM.UserName, gatewayUsr)
	}
	return m
}

// engineStore is the JSON the proxy persists anti-rollback state in.
type engineStore struct {
	EngineID string `json:"engine_id"`
	Boots    uint32 `json:"boots"`
}

func readEngineStore(t *testing.T, path string) engineStore {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("conformance: read engine store: %v", err)
	}
	var st engineStore
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("conformance: parse engine store %s: %v", path, err)
	}
	return st
}
