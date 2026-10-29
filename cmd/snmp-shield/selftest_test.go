package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
)

// selftest_test.go — the pre-flight probes behind `snmp-shield selftest`.
//
// These are the appliance's "test connection" button: an operator runs them
// before a change and trusts the answer. They had no test at all, so every
// line of probeAgent/probeTunnel/probeAgentV3 was exercised only by hand —
// exactly the code where a false "ok" is worse than a false failure. Each
// probe is driven against a real wire peer here, and each failure mode is
// asserted to be a FAIL with a cause (never a panic, never a silent ok).

// --- probeAgent ----------------------------------------------------------------

func TestProbeAgentAgainstDevice(t *testing.T) {
	dev := testkit.NewAgent(t, testkit.AgentOptions{Community: "public"})
	ch := probeAgent(context.Background(), dev.Addr(), "public")
	if !ch.OK {
		t.Fatalf("probe of a live v2c device failed: %s", ch.Detail)
	}
	if !strings.Contains(ch.Detail, `community "public"`) || !strings.Contains(ch.Detail, "v2c") {
		t.Fatalf("probe detail does not describe what it proved: %q", ch.Detail)
	}
	if dev.GETs() == 0 {
		t.Fatal("probe reported ok without the device ever seeing a GET")
	}
}

// TestProbeAgentWrongCommunity is the failure an operator most often hits:
// a community mismatch must be a timeout with a named cause, not an ok.
func TestProbeAgentWrongCommunity(t *testing.T) {
	dev := testkit.NewAgent(t, testkit.AgentOptions{Community: "secret"})
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	ch := probeAgent(ctx, dev.Addr(), "public")
	if ch.OK {
		t.Fatal("probe accepted a device that never answered the community")
	}
	if !strings.Contains(ch.Detail, "no response") {
		t.Fatalf("detail = %q, want a no-response cause", ch.Detail)
	}
}

// TestProbeAgentRetriesOnce pins the deliberate second attempt: some devices
// drop the first query after ARP resolution, and a single attempt would
// report a healthy device as dead. The responder here ignores the first
// datagram and answers the second, exactly like such a device.
func TestProbeAgentRetriesOnce(t *testing.T) {
	var mu sync.Mutex
	seen := 0
	addr := cannedResponder(t, func() []byte {
		mu.Lock()
		seen++
		attempt := seen
		mu.Unlock()
		if attempt == 1 {
			return nil // the ARP-resolution drop
		}
		pdu := msg.BuildPDU(msg.PDUGetResponse, 1, 0, 0, sysDescrVarbinds())
		dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
		if err != nil {
			t.Errorf("build response: %v", err)
			return nil
		}
		return dg
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch := probeAgent(ctx, addr, "public")
	if !ch.OK {
		t.Fatalf("a device that answered the second attempt was reported dead: %s", ch.Detail)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen != 2 {
		t.Fatalf("device saw %d attempts, want 2", seen)
	}
}

func TestProbeAgentRejectsMalformedAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(t *testing.T) []byte
		want   string
	}{
		{
			name: "not snmp",
			answer: func(t *testing.T) []byte {
				return []byte("this is not BER")
			},
			want: "response not SNMP v1/v2c",
		},
		{
			name: "wrong pdu type",
			answer: func(t *testing.T) []byte {
				// A well-formed v2c notification on the request socket: the
				// probe must not mistake "some SNMP came back" for an answer.
				pdu := msg.BuildPDU(msg.PDUSNMPv2Trap, 1, 0, 0, nil)
				dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
				if err != nil {
					t.Fatal(err)
				}
				return dg
			},
			want: "unexpected PDU type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := cannedResponder(t, func() []byte { return tc.answer(t) })
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			ch := probeAgent(ctx, addr, "public")
			if ch.OK {
				t.Fatal("probe accepted a non-answer")
			}
			if !strings.Contains(ch.Detail, tc.want) {
				t.Fatalf("detail = %q, want %q", ch.Detail, tc.want)
			}
		})
	}
}

func TestProbeAgentUnresolvableAddress(t *testing.T) {
	ch := probeAgent(context.Background(), "not an address", "public")
	if ch.OK || !strings.Contains(ch.Detail, "missing port") {
		t.Fatalf("check = %+v, want a resolve failure", ch)
	}
}

// TestSysDescrVarbindsIsConformant pins the probe's request at the byte
// level, because a malformed GET is invisible against a lenient agent and
// makes selftest declare a healthy device dead. Two defects lived here: a
// double-wrapped varbind (a SEQUENCE where the list expects an OID) and a
// missing NULL value.
func TestSysDescrVarbindsIsConformant(t *testing.T) {
	vbs, err := msg.ParseVarbinds(sysDescrVarbinds())
	if err != nil {
		t.Fatalf("the probe's varbind list is not parseable: %v", err)
	}
	if len(vbs) != 1 {
		t.Fatalf("varbinds = %d, want 1", len(vbs))
	}
	if vbs[0].OID != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("oid = %q, want sysDescr.0", vbs[0].OID)
	}
	if vbs[0].Type != 0x05 || len(vbs[0].Value) != 0 {
		t.Fatalf("value = tag 0x%02x %x, want NULL (a GET varbind carries unSpecified)",
			vbs[0].Type, vbs[0].Value)
	}
}

// TestProbeCommunityPrecedence pins which community the probes actually
// send: the user's configured community wins, then the role-specific field,
// then "public". A probe using the wrong one reports a healthy device dead.
func TestProbeCommunityPrecedence(t *testing.T) {
	cfg := &config.Config{}
	if got := agentCommunity(cfg); got != "public" {
		t.Fatalf("agentCommunity(empty) = %q, want public", got)
	}
	cfg.Agent.AgentCommunity = "agentcomm"
	if got := agentCommunity(cfg); got != "agentcomm" {
		t.Fatalf("agentCommunity = %q, want agentcomm", got)
	}
	cfg.Security.Users = []config.UserCfg{{Name: "proxy", Community: "usercomm"}}
	if got := agentCommunity(cfg); got != "usercomm" {
		t.Fatalf("agentCommunity = %q, want the user's community", got)
	}

	gcfg := &config.Config{}
	if got := gatewayCommunity(gcfg); got != "public" {
		t.Fatalf("gatewayCommunity(empty) = %q, want public", got)
	}
	gcfg.Gateway.AgentCommunity = "legacycomm"
	if got := gatewayCommunity(gcfg); got != "legacycomm" {
		t.Fatalf("gatewayCommunity = %q, want legacycomm", got)
	}
}

// --- probeTunnel ---------------------------------------------------------------

func TestProbeTunnelHandshake(t *testing.T) {
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	serveAccepted(l)

	cfg := &config.Config{Role: config.RoleManager}
	cfg.Tunnel = config.Tunnel{
		Mode:        "dtls",
		DialAddrs:   []string{l.Addr().String()},
		PSK:         "text:secret",
		PSKIdentity: "id",
	}
	checks := probeTunnel(context.Background(), cfg)
	if len(checks) != 1 || !checks[0].OK {
		t.Fatalf("checks = %+v, want one successful handshake", checks)
	}
	if !strings.Contains(checks[0].Name, l.Addr().String()) {
		t.Fatalf("check %q does not name the endpoint it probed", checks[0].Name)
	}
}

// TestProbeTunnelPerEndpoint pins the property that makes the manager probe
// useful during an HA failover: every configured endpoint is reported on its
// own, so "one of my two tunnels is dead" is visible instead of averaged.
func TestProbeTunnelPerEndpoint(t *testing.T) {
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode:        "dtls",
		PSK:         []byte("secret"),
		PSKIdentity: []byte("id"),
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	serveAccepted(l)

	dead := freeUDPAddr(t)
	cfg := &config.Config{Role: config.RoleManager}
	cfg.Tunnel = config.Tunnel{
		Mode: "dtls",
		// The live endpoint first: the per-endpoint budgets come out of ONE
		// overall deadline, and a dead first endpoint would eat it (that
		// starvation is asserted separately below).
		DialAddrs:   []string{l.Addr().String(), dead},
		PSK:         "text:secret",
		PSKIdentity: "id",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	checks := probeTunnel(ctx, cfg)
	if len(checks) != 2 {
		t.Fatalf("checks = %d, want one per endpoint", len(checks))
	}
	if !checks[0].OK {
		t.Fatalf("live endpoint reported a failure: %+v", checks[0])
	}
	if checks[1].OK {
		t.Fatalf("dead endpoint reported ok: %+v", checks[1])
	}
	if checks[1].Detail == "" {
		t.Fatal("dead endpoint reported no cause")
	}

	// A deadline already spent must be reported as "not probed", not as a
	// failed handshake: an operator reading "handshake failed" for an
	// endpoint nobody contacted would chase a healthy peer.
	expired, cancel2 := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel2()
	<-expired.Done()
	checks = probeTunnel(expired, cfg)
	if len(checks) != 2 {
		t.Fatalf("checks = %d, want one per endpoint", len(checks))
	}
	for _, ch := range checks {
		if ch.OK || !strings.Contains(ch.Detail, "not probed") {
			t.Fatalf("expired-budget check = %+v, want a not-probed report", ch)
		}
	}
}

func TestProbeTunnelConfigurationErrors(t *testing.T) {
	// No PSK: the probe cannot even try, and must say why.
	cfg := &config.Config{Role: config.RoleManager}
	cfg.Tunnel = config.Tunnel{Mode: "dtls", DialAddrs: []string{"127.0.0.1:1"}}
	checks := probeTunnel(context.Background(), cfg)
	if len(checks) != 1 || checks[0].OK || !strings.Contains(checks[0].Detail, "psk") {
		t.Fatalf("missing-PSK check = %+v", checks)
	}

	// No endpoints: an empty list must not look like success.
	cfg = &config.Config{Role: config.RoleManager}
	cfg.Tunnel = config.Tunnel{Mode: "dtls", PSK: "text:secret"}
	checks = probeTunnel(context.Background(), cfg)
	if len(checks) != 1 || checks[0].OK || !strings.Contains(checks[0].Detail, "no tunnel endpoints") {
		t.Fatalf("no-endpoint check = %+v", checks)
	}
}

// --- probeAgentV3 --------------------------------------------------------------

func TestProbeAgentV3AgainstAgent(t *testing.T) {
	agent := newFakeV3Agent(t)
	ch := probeAgentV3(context.Background(), v3SelftestCfg(agent.addr))
	if !ch.OK {
		t.Fatalf("probe of a live v3 agent failed: %s", ch.Detail)
	}
	if !strings.Contains(ch.Detail, `user "proxy"`) || !strings.Contains(ch.Detail, "discovery + authPriv GET ok") {
		t.Fatalf("probe detail does not describe what it proved: %q", ch.Detail)
	}
	if agent.discoveries() != 1 || agent.gets() != 1 {
		t.Fatalf("agent saw %d discoveries and %d GETs, want 1 and 1",
			agent.discoveries(), agent.gets())
	}
}

// TestProbeAgentV3SkipsStrayDatagrams pins v3Exchange's filter: a peer (or
// a middlebox) that emits a clear datagram on the same socket must not be
// mistaken for the v3 answer, or the probe reports a healthy agent broken.
func TestProbeAgentV3SkipsStrayDatagrams(t *testing.T) {
	agent := newFakeV3Agent(t, func(a *fakeV3Agent) { a.stray = true })
	ch := probeAgentV3(context.Background(), v3SelftestCfg(agent.addr))
	if !ch.OK {
		t.Fatalf("probe failed with a stray clear datagram in the stream: %s", ch.Detail)
	}
}

func TestProbeAgentV3Failures(t *testing.T) {
	t.Run("no users", func(t *testing.T) {
		cfg := v3SelftestCfg("127.0.0.1:1")
		cfg.Security.Users = nil
		ch := probeAgentV3(context.Background(), cfg)
		if ch.OK || !strings.Contains(ch.Detail, "no security.users") {
			t.Fatalf("check = %+v", ch)
		}
	})

	t.Run("bad auth protocol", func(t *testing.T) {
		cfg := v3SelftestCfg("127.0.0.1:1")
		cfg.Security.Users[0].AuthProtocol = "rot13"
		ch := probeAgentV3(context.Background(), cfg)
		if ch.OK || ch.Detail == "" {
			t.Fatalf("check = %+v", ch)
		}
	})

	t.Run("noAuthNoPriv user", func(t *testing.T) {
		cfg := v3SelftestCfg("127.0.0.1:1")
		cfg.Security.Users[0].AuthProtocol = "none"
		cfg.Security.Users[0].PrivProtocol = "none"
		ch := probeAgentV3(context.Background(), cfg)
		if ch.OK || !strings.Contains(ch.Detail, "authPriv") {
			t.Fatalf("check = %+v", ch)
		}
	})

	t.Run("no discovery answer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		ch := probeAgentV3(ctx, v3SelftestCfg(freeUDPAddr(t)))
		if ch.OK || !strings.Contains(ch.Detail, "discovery") {
			t.Fatalf("check = %+v", ch)
		}
	})

	t.Run("report without engineID", func(t *testing.T) {
		agent := newFakeV3Agent(t, func(a *fakeV3Agent) { a.reportWithoutEngine = true })
		ch := probeAgentV3(context.Background(), v3SelftestCfg(agent.addr))
		if ch.OK || !strings.Contains(ch.Detail, "no engineID") {
			t.Fatalf("check = %+v", ch)
		}
	})

	// The one that matters most: an agent that answers discovery but whose
	// authPriv answer does not verify must NOT be reported healthy. A
	// probe that skips digest verification would bless a device that no
	// real manager can talk to.
	t.Run("tampered authPriv answer", func(t *testing.T) {
		agent := newFakeV3Agent(t, func(a *fakeV3Agent) { a.corruptResponses = true })
		ch := probeAgentV3(context.Background(), v3SelftestCfg(agent.addr))
		if ch.OK {
			t.Fatal("probe accepted an answer whose digest does not verify")
		}
		if !strings.Contains(ch.Detail, "response rejected") {
			t.Fatalf("detail = %q, want a rejected-response cause", ch.Detail)
		}
	})
}

// --- probeCertExpiry -----------------------------------------------------------

func TestProbeCertExpiry(t *testing.T) {
	long := writeCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	soon := writeCert(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	expired := writeCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	if ch := probeCertExpiry(long); !ch.OK || !strings.Contains(ch.Detail, "valid until") {
		t.Fatalf("long-lived cert = %+v", ch)
	}
	// A warning still passes: an expiring cert is not an outage yet.
	if ch := probeCertExpiry(soon); !ch.OK || !strings.Contains(ch.Detail, "renew soon") {
		t.Fatalf("soon-expiring cert = %+v", ch)
	}
	if ch := probeCertExpiry(expired); ch.OK || !strings.Contains(ch.Detail, "EXPIRED") {
		t.Fatalf("expired cert = %+v", ch)
	}
	if ch := probeCertExpiry(""); ch.OK || !strings.Contains(ch.Detail, "no cert configured") {
		t.Fatalf("empty path = %+v", ch)
	}
	if ch := probeCertExpiry(filepath.Join(t.TempDir(), "missing.pem")); ch.OK || ch.Detail == "" {
		t.Fatalf("missing file = %+v", ch)
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ch := probeCertExpiry(junk); ch.OK || !strings.Contains(ch.Detail, "no PEM block") {
		t.Fatalf("non-PEM file = %+v", ch)
	}
}

// --- runRole exit codes --------------------------------------------------------

// TestRunRoleExitCodes pins the startup contract a service manager sees: a
// flag typo, an unusable log level, an invalid config and a missing config
// file must each exit non-zero and do it without starting anything. The
// success path blocks in proxy.Run and is covered by the role tests there.
func TestRunRoleExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		role string
		args []string
		want int
	}{
		{"unknown flag", "manager", []string{"--no-such-flag"}, 2},
		{"bad log level", "manager", []string{"--log-level", "loud"}, 1},
		{"invalid flags config", "manager", []string{"--listen", ":0"}, 2},
		{"missing config file", "agent", []string{"--config", filepath.Join(t.TempDir(), "absent.yaml")}, 1},
		{"invalid config file", "gateway", []string{"--config", writeFile(t, "role: gateway\nsecurity:\n  mode: nope\n")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runRole(tc.role, tc.args); got != tc.want {
				t.Fatalf("runRole(%s, %v) = %d, want %d", tc.role, tc.args, got, tc.want)
			}
		})
	}
}

// TestSelftestAgentEndToEnd runs the whole subcommand the way an operator
// does — flags in, report out — against a live v2c device and a dead one.
// It is the wiring test for runSelftest's probe dispatch and the exit-code
// contract a deployment script depends on.
func TestSelftestAgentEndToEnd(t *testing.T) {
	dev := testkit.NewAgent(t, testkit.AgentOptions{Community: "public"})
	args := func(agentAddr string) []string {
		return []string{
			"--role", "agent",
			"--tunnel-addr", "127.0.0.1:0",
			"--psk", "aabbccdd",
			"--auth-pass", "authpass",
			"--priv-pass", "privpass",
			"--agent", agentAddr,
			"--community", "public",
		}
	}

	out := captureStdout(t, func() {
		if rc := runSelftest(args(dev.Addr())); rc != 0 {
			t.Fatalf("selftest against a live device = %d, want 0", rc)
		}
	})
	if !strings.Contains(out, "GET sysDescr.0 ok") {
		t.Fatalf("selftest did not report the agent probe: %q", out)
	}
	if !strings.Contains(out, "selftest passed") {
		t.Fatalf("selftest did not print its verdict: %q", out)
	}

	// A dead agent must fail the run, not pass on the config checks alone.
	_ = captureStdout(t, func() {
		if rc := runSelftest(args(freeUDPAddr(t))); rc != 1 {
			t.Fatalf("selftest against a dead device = %d, want 1", rc)
		}
	})
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

// --- helpers -------------------------------------------------------------------

// cannedResponder answers every datagram with the bytes answer returns.
func cannedResponder(t *testing.T, answer func() []byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("responder bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			_, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// A nil answer means "stay silent". Writing it anyway would
			// deliver a zero-length datagram, which is not silence: the
			// probe would read it and report a malformed answer instead of
			// a timeout.
			if out := answer(); len(out) > 0 {
				_, _ = conn.WriteTo(out, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// freeUDPAddr returns a loopback UDP address nothing is listening on.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe free addr: %v", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

// serveAccepted drives the server side of every accepted DTLS conn until
// the listener closes. A pion server does not start its handshake until the
// app reads, so "accept and discard" would hang the probe.
func serveAccepted(l net.Listener) {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()
}

// writeFile writes body to a temp file and returns its path.
func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// writeCert issues a self-signed certificate with the given validity and
// returns the PEM path (probeCertExpiry only reads the leaf).
func writeCert(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "snmp-shield selftest"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// v3SelftestCfg is an usm-manager-gateway config whose first user matches
// the fake agent's credentials.
func v3SelftestCfg(agentAddr string) *config.Config {
	return &config.Config{
		Role:     config.RoleGateway,
		Gateway:  config.GatewayRole{AgentAddr: agentAddr},
		Security: v3SelftestSecurity(),
	}
}

func v3SelftestSecurity() config.Security {
	return config.Security{
		Mode: "usm-manager-gateway",
		Users: []config.UserCfg{{
			Name:           "proxy",
			AuthProtocol:   "sha",
			AuthPassphrase: "authpass",
			PrivProtocol:   "aes",
			PrivPassphrase: "privpass",
		}},
	}
}

// fakeV3Agent is the smallest conformant USM agent: it answers RFC 3414
// discovery with a Report naming its own engine, and one authPriv GET with
// a signed+encrypted GetResponse. It exists so the probe is judged on the
// wire rather than by a mock that agrees with it.
//
// internal/usm has a richer fixture, but it lives in package usm and cannot
// be imported here without an import cycle (usm's own tests are internal).
type fakeV3Agent struct {
	conn net.PacketConn
	addr string
	eng  []byte
	prof *usm.Profiles

	reportWithoutEngine bool
	corruptResponses    bool
	stray               bool

	mu    sync.Mutex
	discN int
	getN  int
}

const (
	fakeAgentBoots = 7
	fakeAgentTime  = 1000
)

// newFakeV3Agent starts the fake agent. tune runs BEFORE the read loop
// starts, so behaviour flags never race with the handler.
func newFakeV3Agent(t *testing.T, tune ...func(*fakeV3Agent)) *fakeV3Agent {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake v3 agent bind: %v", err)
	}
	eng := []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 0x73, 0x65, 0x6c, 0x66}
	profs, err := usm.NewProfilesFromSecurity(v3SelftestSecurity(), eng)
	if err != nil {
		t.Fatalf("fake v3 agent profiles: %v", err)
	}
	a := &fakeV3Agent{conn: conn, addr: conn.LocalAddr().String(), eng: eng, prof: profs}
	for _, fn := range tune {
		fn(a)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go a.loop()
	return a
}

func (a *fakeV3Agent) discoveries() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.discN
}

func (a *fakeV3Agent) gets() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.getN
}

func (a *fakeV3Agent) loop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		a.handle(append([]byte(nil), buf[:n]...), from)
	}
}

func (a *fakeV3Agent) handle(dg []byte, from net.Addr) {
	m, err := msg.ParseV3(dg)
	if err != nil {
		return
	}
	if m.Header.MsgFlags&msg.MsgFlagReportable != 0 && m.USM.UserName == "" {
		a.mu.Lock()
		a.discN++
		a.mu.Unlock()
		eng := a.eng
		if a.reportWithoutEngine {
			eng = nil
		}
		pdu := msg.BuildPDU(msg.PDUReport, int32(m.Header.MsgID), 0, 0, nil)
		out, berr := msg.BuildV3(msg.V3Header{
			MsgID:      m.Header.MsgID,
			MsgMaxSize: msg.DefaultMsgMaxSize,
			MsgFlags:   msg.MsgFlagReportable,
			SecModel:   msg.SecurityModelUSM,
		}, msg.USMParams{EngineID: eng, Boots: fakeAgentBoots, Time: fakeAgentTime},
			msg.BuildScoped(a.eng, []byte{}, pdu), nil)
		if berr != nil {
			return
		}
		a.send(out, from)
		return
	}

	_, plain, err := usm.UnwrapV3(a.prof, m, dg)
	if err != nil {
		return
	}
	pduType, fields, err := msg.ParsePDU(plain)
	if err != nil || pduType != msg.PDUGetRequest {
		return
	}
	a.mu.Lock()
	a.getN++
	a.mu.Unlock()

	u, ok := a.prof.Lookup("proxy")
	if !ok {
		return
	}
	respPDU := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
	scoped := msg.BuildScoped(a.eng, []byte{}, respPDU)
	privParams := make([]byte, 8) // one-shot probe peer; the salt is not reused
	authParams := make([]byte, u.Profile().AuthProtocol.MacLength())
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      m.Header.MsgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(msg.MsgFlagAuth | msg.MsgFlagPriv),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   a.eng,
		Boots:      fakeAgentBoots,
		Time:       fakeAgentTime,
		UserName:   "proxy",
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, func(plainPDU []byte) ([]byte, error) {
		return usm.EncryptScoped(u.Profile().PrivProtocol, u.PrivKey(),
			fakeAgentBoots, fakeAgentTime, privParams, plainPDU)
	})
	if err != nil {
		return
	}
	if err := usm.SignV3(out, u.Profile().AuthProtocol, u.AuthKey()); err != nil {
		return
	}
	if a.corruptResponses {
		// Flip a byte inside the encrypted scopedPDU: the digest is now
		// wrong, which the probe must notice.
		out[len(out)-1] ^= 0xff
	}
	a.send(out, from)
}

func (a *fakeV3Agent) send(dg []byte, to net.Addr) {
	if a.stray {
		// A clear datagram ahead of the v3 answer, as a confused or
		// spoofed source would produce.
		if pdu, err := msg.BuildV1V2c(msg.Version2c, []byte("public"),
			msg.BuildPDU(msg.PDUSNMPv2Trap, 1, 0, 0, nil)); err == nil {
			_, _ = a.conn.WriteTo(pdu, to)
		}
	}
	_, _ = a.conn.WriteTo(dg, to)
}
