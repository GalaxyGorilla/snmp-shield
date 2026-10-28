package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// dockerNetSNMPImage is built by `make peers`
// (test/peers/netsnmp-docker/Dockerfile): a current net-snmp with OpenSSL,
// i.e. one that can actually speak `dtls:` and can act as a modern clear-leg
// peer. The host's own net-snmp may be Apple's 5.6.2.1 (2010), which has no
// TLS support at all.
const dockerNetSNMPImage = "snmp-shield-net-snmp:peer"

// dockerHost is how a container reaches this machine. net-snmp's TSM client
// cannot be pointed at an IP at all — it compares the server certificate
// against the *name* you dial ("No matching names in the certificate to
// match the expected 127.0.0.1") — so the certificate must carry this name
// and the target must be `dtls:host.docker.internal:port`. The clear-leg
// peer needs it for the same routing reason (a container cannot reach the
// host's 127.0.0.1).
const dockerHost = "host.docker.internal"

// dockerPeer runs the net-snmp adapter inside the net-snmp container.
//
// Why: the host's net-snmp is whatever the OS ships — Apple's is 5.6.2.1,
// released in 2010, and several notes in this repository are explicitly
// about *its* quirks. Testing only against it means the v1/v2c/v3 legs are
// validated against a stack nobody deploys. The 5.9 container already
// exists for the RFC 6353 TSM client, so the same image (plus python3) can
// run the ordinary adapter and cover the clear legs with a current release.
//
// The mechanics are boring on purpose: it is the *same* peer_netsnmp.py and
// the same flag contract, so a disagreement between the two net-snmp
// versions is a finding about net-snmp or about us, never an adapter
// difference.
type dockerPeer struct {
	name    string
	stack   string
	image   string
	adapter string

	once    sync.Once
	unavail string
}

func newDockerNetSNMPPeer() *dockerPeer {
	return &dockerPeer{
		name:    "netsnmp59",
		stack:   "net-snmp 5.9 (Debian bookworm, Docker)",
		image:   dockerNetSNMPImage,
		adapter: "peer_netsnmp.py",
	}
}

func (p *dockerPeer) Name() string  { return p.name }
func (p *dockerPeer) Stack() string { return p.stack }

// NeedsHostRoute marks a peer that does not share this machine's loopback: a
// container reaches the host by bridge address, so the fixture must bind a
// routable address and the target has to be rewritten.
func (p *dockerPeer) NeedsHostRoute() bool { return true }

func (p *dockerPeer) Unavailable() string {
	p.once.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			p.unavail = "docker not installed — run `make peers` for the 5.9 peer"
			return
		}
		if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
			p.unavail = fmt.Sprintf("docker daemon unavailable (%s)", firstLine(string(out)))
			return
		}
		if err := exec.Command("docker", "image", "inspect", p.image).Run(); err != nil {
			p.unavail = fmt.Sprintf("image %s missing — run `make peers`", p.image)
			return
		}
		// The adapter is mounted, not baked in, so python3 must exist in
		// the image. Fail loudly here rather than as a per-scenario
		// adapter error (the image may be an older build).
		if out, err := exec.Command("docker", "run", "--rm", p.image, "python3", "--version").CombinedOutput(); err != nil {
			p.unavail = fmt.Sprintf("image %s has no python3 (%s) — rebuild with `make peers`",
				p.image, firstLine(string(out)))
		}
	})
	return p.unavail
}

func (p *dockerPeer) Run(ctx context.Context, req Request) (Result, error) {
	// The container can only reach the host through its bridge name.
	req.Target = dockerTarget(req.Target)
	// v1 traps carry an agent-address in the PDU; keep it meaningful from
	// inside the container too (it is informational, not a destination).
	if req.AgentAddr != "" {
		req.AgentAddr = dockerTarget(req.AgentAddr)
	}
	args := []string{
		"run", "--rm",
		"--add-host", dockerHost + ":host-gateway",
		"-v", peersDir() + ":/peers:ro",
		p.image,
		"python3", "/peers/" + p.adapter,
		string(req.Verb),
	}
	args = append(args, adapterArgs(req)...)

	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil && len(out) == 0 {
		return Result{}, fmt.Errorf("%s: docker run: %w", p.name, err)
	}
	var res Result
	if jerr := json.Unmarshal(lastJSONLine(out), &res); jerr != nil {
		return Result{}, fmt.Errorf("%s: unparseable adapter output (%v): %s", p.name, jerr, firstLine(string(out)))
	}
	return res, nil
}

// dockerTarget rewrites a loopback target to the name a container can dial.
func dockerTarget(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return net.JoinHostPort(dockerHost, port)
	}
	return addr
}

// peerNeedsHostRoute reports whether a peer lives outside this machine's
// network namespace (a container). Fixtures use it to decide where to bind:
// loopback is enough for a native peer, while a container needs a wildcard
// bind (it cannot reach the host's loopback).
func peerNeedsHostRoute(p Peer) bool {
	type hostRouted interface{ NeedsHostRoute() bool }
	h, ok := p.(hostRouted)
	return ok && h.NeedsHostRoute()
}

// peerFront allocates a leg the peer under test can reach and returns
// {bind, dial}: bind is what the proxy is told to listen on, dial is what
// the harness and the peer's adapter (after rewriting) target.
func peerFront(t testing.TB, p Peer) (bind, dial string) {
	t.Helper()
	if peerNeedsHostRoute(p) {
		bind = testkit.FreeUDPPort(t, "[::]")
		if _, port, err := net.SplitHostPort(bind); err == nil {
			return bind, net.JoinHostPort("127.0.0.1", port)
		}
	}
	dial = testkit.FreeUDPPort(t, "")
	return dial, dial
}
