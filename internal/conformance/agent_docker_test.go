package conformance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A REAL v3 agent from the peer image, for the usm-manager-gateway scenarios.
//
// Why a second agent fixture: the host's snmpd is whatever the OS ships —
// Apple's is 5.6.2.1, released in 2010 — while the proxy's job on this leg
// (RFC 3414 discovery, key localization to somebody else's engine, signing,
// encrypting and parsing THEIR answer) is exactly the kind of code a release
// change can invalidate. The Debian peer image already carries snmpd 5.9.3
// for the same reason it carries the CLI, so the current release costs one
// `docker run` rather than another toolchain.
//
// The container is a fixture, never a service: it publishes on 127.0.0.1
// only, gets a random name, and is force-removed at cleanup. A failure to
// start is an environment skip (a failure under `make conformance-required`),
// matching how a missing host snmpd is treated.

// dockerV3Snmpd is a net-snmp agent running inside the peer image.
type dockerV3Snmpd struct {
	addr string
	name string
	once sync.Once
}

func (a *dockerV3Snmpd) Addr() string { return a.addr }

func (a *dockerV3Snmpd) Stop(t *testing.T) {
	t.Helper()
	a.once.Do(func() {
		// Read the log before removing: it is the only evidence when the
		// agent refused its config or died mid-test.
		logs, _ := exec.Command("docker", "logs", a.name).CombinedOutput()
		_ = exec.Command("docker", "rm", "-f", a.name).Run()
		if t.Failed() {
			t.Logf("docker snmpd (%s) output:\n%s", a.name, logs)
		}
	})
}

// requireDockerSnmpd skips unless the peer image can also act as the v3
// agent. The capability check is deliberate: an image built before snmpd was
// installed would otherwise fail with a startup timeout that looks like a
// proxy bug, instead of telling the operator to rebuild.
func requireDockerSnmpd(t *testing.T) {
	t.Helper()
	requireDockerNetSNMP(t)
	if out, err := exec.Command("docker", "run", "--rm", "--entrypoint", "sh", dockerNetSNMPImage,
		"-c", "command -v snmpd").CombinedOutput(); err != nil {
		skipOrFail(t, "image %s has no snmpd (%s) — rebuild with `make peers`",
			dockerNetSNMPImage, firstLine(string(out)))
	}
}

// startDockerV3Snmpd launches net-snmp 5.9.3 with a v3 authPriv user and
// returns once a direct v3 GET has answered (so a broken fixture is never
// blamed on the proxy).
//
// The config is the same shape as the native fixture's, with two 5.9-isms:
// `agentaddress udp:1161` names the transport explicitly (what the published
// container port forwards to), and `rouser` grants the created user access.
// The second one is a real divergence from the host build: Apple's 5.6.2.1
// rejects `rouser` as an unknown token and grants a created user access
// implicitly, while 5.9 without any access-control directive answers every
// request with AuthorizationError and logs "no access control information
// configured". Without `rouser` this fixture would look like a proxy bug.
func startDockerV3Snmpd(t *testing.T) v3AgentFixture {
	t.Helper()
	requireDockerSnmpd(t)

	dir := t.TempDir()
	conf := filepath.Join(dir, "snmpd.conf")
	body := "createUser " + mgwUser + " SHA " + authPass + " AES " + privPass + "\n" +
		"rouser " + mgwUser + "\n" +
		"agentaddress udp:1161\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatalf("conformance: write docker snmpd config: %v", err)
	}

	// Docker assigns the host port and reports it (`-p 127.0.0.1::1161/udp`)
	// instead of us probing a free port and publishing it afterwards: the
	// probe/publish gap is a TOCTOU race that another fixture can lose a port
	// to. See startTrapd for the failure it actually caused.
	name := fmt.Sprintf("snmp-shield-snmpd-%d-%d", os.Getpid(), time.Now().UnixNano())

	// -C: do not read the image's default config. The persistent dir must
	// exist before createUser runs, and it stays inside the container: a
	// throwaway engineID is exactly right for a fixture.
	args := []string{
		"run", "-d", "--name", name,
		"-p", "127.0.0.1::1161/udp",
		"-v", dir + ":/peers:ro",
		"-e", "SNMP_PERSISTENT_DIR=/home/peer/.snmp-persist",
		dockerNetSNMPImage,
		"sh", "-c", "mkdir -p /home/peer/.snmp-persist && exec snmpd -f -Le -C -c /peers/snmpd.conf",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		skipOrFail(t, "docker snmpd cannot start (%s)", firstLine(string(out)))
	}
	pubOut, perr := exec.Command("docker", "port", name, "1161/udp").Output()
	if perr != nil {
		t.Fatalf("conformance: docker port: %v", perr)
	}
	addr := publishedLoopback(t, strings.TrimSpace(string(pubOut)))
	agent := &dockerV3Snmpd{addr: addr, name: name}
	t.Cleanup(func() { agent.Stop(t) })
	waitV3Agent(t, addr)
	return agent
}
