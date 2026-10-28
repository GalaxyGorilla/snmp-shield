// manager_gateway_test.go: the reverse gateway (legacy v2c manager in,
// v3 USM authPriv out) against a REAL net-snmp agent.
//
// This is the leg the other conformance scenarios cannot reach: there the
// proxy terminates USM itself, so its v3 code is only ever the authoritative
// engine. Here the proxy is a v3 COMMAND GENERATOR — it must perform RFC 3414
// discovery, localize keys to somebody else's engine, sign, encrypt and parse
// their answer. Getting msgMaxSize, salt handling or the boots/time window
// subtly wrong is invisible to a Go-only harness, because the fake agent uses
// the same encoders.
package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// mgwUser is the v3 user configured on the real snmpd. The proxy
// authenticates as this user; the v2c manager never sees the credentials.
const mgwUser = "authPrivUser"

// snmpdAgent is a real net-snmp agent process with a v3 authPriv user.
type snmpdAgent struct {
	addr string
	cmd  *exec.Cmd
	log  *lockedBuffer
	done chan struct{}
	once sync.Once
}

func (a *snmpdAgent) stop(t *testing.T) {
	t.Helper()
	a.once.Do(func() {
		_ = a.cmd.Process.Kill()
		<-a.done
	})
	if t.Failed() {
		t.Logf("snmpd output:\n%s", a.log.String())
	}
}

// startV3Snmpd launches the system snmpd with a throwaway config and a
// throwaway persistent store.
//
// Portability notes learned on this host (Apple net-snmp 5.6.2.1): `rouser`
// and `rwuser` are unknown tokens, `createUser` only takes effect when
// SNMP_PERSISTENT_DIR is writable (otherwise the user silently never
// exists), and the stock build logs "no log handling" noise to stderr. The
// agent still reads with the created user, which is all a v3 command
// generator needs.
func startV3Snmpd(t *testing.T) *snmpdAgent {
	t.Helper()
	path := "/usr/sbin/snmpd"
	if p, err := exec.LookPath("snmpd"); err == nil {
		path = p
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("snmpd not installed (%s): the v3 agent leg is unverified on this host", path)
	}

	dir := t.TempDir()
	addr := testkit.FreeUDPPort(t, "127.0.0.1")
	conf := filepath.Join(dir, "snmpd.conf")
	body := "createUser " + mgwUser + " SHA " + authPass + " AES " + privPass + "\n" +
		"agentaddress " + addr + "\n"
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatalf("conformance: write snmpd config: %v", err)
	}

	cmd := exec.Command(path, "-f", "-Le", "-C", "-c", conf)
	cmd.Env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+dir)
	lb := &lockedBuffer{}
	cmd.Stdout = lb
	cmd.Stderr = lb
	if err := cmd.Start(); err != nil {
		t.Skipf("snmpd cannot start here: %v", err)
	}
	agent := &snmpdAgent{addr: addr, cmd: cmd, log: lb, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(agent.done)
	}()
	t.Cleanup(func() { agent.stop(t) })

	testkit.WaitUDPBound(t, addr, 10*time.Second)

	// Prove the credentials work before blaming the proxy: a v3 GET straight
	// at snmpd must answer. If this fails the fixture is broken, not the
	// code under test.
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		g := newSession(t, addr, "3", time.Second)
		g.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName = mgwUser
		err := g.Connect()
		if err == nil {
			_, err = g.Get([]string{sysDescr})
			_ = g.Conn.Close()
		}
		if err == nil {
			return agent
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("snmpd never answered a direct v3 GET at %s: %v", addr, last)
	return nil
}

// startManagerGateway runs the real binary in usm-manager-gateway mode
// against the given v3 agent and returns the clear front leg, its trap
// listener and the legacy manager's clear trap sink.
func startManagerGateway(t *testing.T, agentAddr string) (front, trapListen string, sink *testkit.TrapSink) {
	t.Helper()
	front = testkit.FreeUDPPort(t, "")
	trapListen = testkit.FreeUDPPort(t, "")
	sink = testkit.NewAnsweringTrapSink(t)
	startProxy(t, "manager-gateway", "gateway",
		"--security", "usm-manager-gateway",
		"--listen", front,
		"--agent", agentAddr,
		"--user", mgwUser,
		"--auth-pass", authPass,
		"--priv-pass", privPass,
		"--trap-listen", trapListen,
		"--trap-sink", sink.Addr(),
		"--log-level", "debug",
	)
	waitFront(t, front)
	waitFront(t, trapListen)
	return front, trapListen, sink
}

// TestManagerGatewayRealAgent drives the v3 generator leg with each vendor
// on the clear leg. The proxy has to speak standard USM toward a stack it
// does not control and hand the manager plain v2c.
func TestManagerGatewayRealAgent(t *testing.T) {
	agent := startV3Snmpd(t)

	eachPeer(t, func(t *testing.T, p Peer) {
		front, trapListen, sink := startManagerGateway(t, agent.addr)

		req := func(verb Verb, oids ...string) Request {
			return Request{
				Verb: verb, Version: "2c", Community: community,
				Target: front, OIDs: oids,
				// The first request pays for RFC 3414 discovery, so give
				// the vendor more than its usual 2s budget.
				Timeout: 5, Retries: 1,
			}
		}

		t.Run("get", func(t *testing.T) {
			res := mustRun(t, p, req(VerbGet, sysDescr))
			requireOK(t, res)
			requireVarbind(t, res, sysDescr, "OctetString", "")
		})

		t.Run("getnext", func(t *testing.T) {
			res := mustRun(t, p, req(VerbGetNext, sysDescr))
			requireOK(t, res)
			requireVarbind(t, res, "1.3.6.1.2.1.1.2.0", "", "")
		})

		t.Run("walk", func(t *testing.T) {
			res := mustRun(t, p, req(VerbWalk, "1.3.6.1.2.1.1"))
			requireOK(t, res)
			if len(res.Varbinds) < 3 {
				t.Fatalf("walk returned %d varbinds: %v", len(res.Varbinds), res.Varbinds)
			}
		})

		t.Run("set-is-answered-not-timed-out", func(t *testing.T) {
			// snmpd's user is read-only: the refusal must travel back as a
			// PDU error-status. A timeout here means the v3 answer could
			// not be verified/decrypted and was dropped.
			start := time.Now()
			r := req(VerbSet)
			r.Varbinds = []string{sysDescr + "=string:conformance"}
			res := mustRun(t, p, r)
			if res.OK {
				t.Fatalf("read-only snmpd accepted a SET: %v", res.Varbinds)
			}
			if res.ErrorKind == KindTimeout {
				t.Fatalf("SET timed out: the v3 response never made it back (%s)", res.Error)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("refusal took %s", elapsed)
			}
		})

		t.Run("v3-on-the-clear-front-leg-is-ignored", func(t *testing.T) {
			// By design the clear manager leg is v2c-only; that rejection is
			// the protection. A vendor sending v3 must see silence, not an
			// answer from either the proxy or the agent.
			res := mustRun(t, p, Request{
				Verb: VerbGet, Version: "3", Level: "authpriv",
				User: mgwUser, Auth: authPass, Priv: privPass,
				Target: front, OIDs: []string{sysDescr},
				Timeout: 2, Retries: 0,
			})
			requireRefused(t, res, KindTimeout)
		})

		t.Run("v3-trap-is-relayed-clear", func(t *testing.T) {
			// The agent fires a v3 authPriv trap with its OWN engine; the
			// proxy has to verify and decrypt it by localizing keys to the
			// wire engineID (nothing tells it that engine in advance).
			const trapOID = "1.3.6.1.4.1.99.7.1"
			res := mustRun(t, p, Request{
				Verb: VerbTrap, Version: "3", Level: "authpriv",
				User: mgwUser, Auth: authPass, Priv: privPass,
				Target: trapListen, OIDs: []string{trapOID},
				Timeout: 2,
			})
			skipUnsupported(t, res)
			requireOK(t, res)
			dg := sink.WaitForTrapOID(t, trapOID, 10*time.Second)
			info, err := msg.Peek(dg)
			if err != nil {
				t.Fatalf("relayed notification is undecodable: %v", err)
			}
			if info.Version != msg.Version2c {
				t.Fatalf("relayed notification version = %d, want v2c", info.Version)
			}
			if got, ok := msg.TrapOID(dg); !ok || got != trapOID {
				t.Fatalf("relayed trap OID = %q (ok=%v), want %q", got, ok, trapOID)
			}
		})

		t.Run("v3-inform-is-answered", func(t *testing.T) {
			// An inform is confirmed by the proxy itself, in v3, toward a
			// sender whose engine we have never seen before. The vendor
			// decides whether the confirmation is acceptable — this is the
			// path where "silently reply with the wrong msgID" is fatal.
			const trapOID = "1.3.6.1.4.1.99.7.2"
			res := mustRun(t, p, Request{
				Verb: VerbInform, Version: "3", Level: "authpriv",
				User: mgwUser, Auth: authPass, Priv: privPass,
				Target: trapListen, OIDs: []string{trapOID},
				Timeout: 4, Retries: 1,
			})
			skipUnsupported(t, res)
			if !res.OK {
				t.Fatalf("inform was not confirmed by the proxy (kind=%q): %s", res.ErrorKind, res.Error)
			}
			dg := sink.WaitForTrapOID(t, trapOID, 10*time.Second)
			info, err := msg.Peek(dg)
			if err != nil || info.Version != msg.Version2c {
				t.Fatalf("relayed inform is not clear v2c: version %d (err %v)", info.Version, err)
			}
		})
	})
}
