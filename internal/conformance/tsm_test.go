package conformance

import (
	"fmt"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// TestTSMGatewayVendorClient drives the tsm-gateway with a *current*
// net-snmp speaking RFC 6353 SNMP-over-DTLS as a third-party client.
//
// This is the one gap the rest of the matrix cannot close: the host's
// net-snmp (Apple 5.6.2.1) has no TLS transport at all, so every other TSM
// assertion in this repository is written against our own DTLS stack. Here a
// vendor stack performs the handshake, presents a client certificate, and
// judges our TSM response echo rules (msgID, request-id, contextEngineID,
// security-level flags) — the exact class of mistake that gosnmp tolerates
// and net-snmp does not.
//
// The proxy runs on the host and the client in a container, so the proxy
// listens on [::] (a container reaches it as host.docker.internal, and
// net-snmp refuses to check a certificate against an IP address) and the
// server certificate must carry that name.
func TestTSMGatewayVendorClient(t *testing.T) {
	requireDockerNetSNMP(t)

	pki := testkit.NewPKIWithNames(t, dockerHost)
	agent := newDevice(t, testkit.AgentOptions{})
	target := startTSMGateway(t, pki, agent)
	home := tsmClientHome(t, pki.ClientCrt, pki.ClientKey, pki.CAFile)
	version := netsnmpVersion(t)

	// run performs one client operation; every success assertion below is on
	// the device side too, because "the vendor printed a value" alone does
	// not prove the request was actually forwarded as clear v2c.
	run := func(t *testing.T, cmd ...string) string {
		t.Helper()
		out, ok := runTSMClient(t, home, cmd...)
		if !ok {
			t.Fatalf("%s failed against %s:\n%s", cmd[0], version, out)
		}
		return out
	}

	t.Run("get", func(t *testing.T) {
		before := agent.GETs()
		// -On: numeric OIDs, so the assertion does not depend on MIB files
		// being installed in the image.
		out := run(t, "snmpget", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "5", "-r", "1", target, sysDescr)
		requireContains(t, out, sysDescr, "the vendor did not print the requested OID")
		requireContains(t, out, "testkit fake agent v1", "the device's value did not survive the DTLS leg")
		if agent.GETs() <= before {
			t.Fatalf("the gateway answered without forwarding anything to the device (%d -> %d)", before, agent.GETs())
		}
	})

	t.Run("getnext", func(t *testing.T) {
		out := run(t, "snmpgetnext", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "5", "-r", "1", target, sysDescr)
		requireContains(t, out, "1.3.6.1.2.1.1.2.0", "GETNEXT did not advance to the next object")
	})

	t.Run("walk", func(t *testing.T) {
		out := run(t, "snmpwalk", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "5", "-r", "1", target, "1.3.6.1.2.1.1")
		requireContains(t, out, "1.3.6.1.2.1.1.1.0", "sysDescr is missing from the walk")
		requireContains(t, out, "1.3.6.1.2.1.1.5.0", "sysName is missing from the walk")
		requireContains(t, out, "1.3.6.1.2.1.1.3.0", "sysUpTime is missing from the walk")
	})

	t.Run("set", func(t *testing.T) {
		before := agent.SETs()
		out := run(t, "snmpset", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "5", "-r", "1", target, sysDescr, "s", "set-through-dtls")
		requireContains(t, out, "set-through-dtls", "the SET answer did not echo the written value")
		if agent.SETs() != before+1 {
			t.Fatalf("device saw %d SETs, want %d: the write did not cross the TSM leg", agent.SETs(), before+1)
		}
	})

	t.Run("untrusted-client", func(t *testing.T) {
		// A client certificate from a foreign CA: the DTLS handshake must
		// fail, and nothing may reach the device. This is the gateway's
		// whole security claim on the TSM leg (the certificate *is* the SNMP
		// authentication), so it is worth pinning from the vendor side.
		foreign := testkit.NewPKI(t)
		foreignHome := tsmClientHome(t, foreign.ClientCrt, foreign.ClientKey, foreign.CAFile)

		before := agent.GETs()
		out, ok := runTSMClient(t, foreignHome, "snmpget", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "2", "-r", "1", target, sysDescr)
		if ok {
			t.Fatalf("a client certificate from another CA was accepted:\n%s", out)
		}
		if agent.GETs() != before {
			t.Fatalf("the rejected client's request reached the device (%d -> %d)", before, agent.GETs())
		}
	})
}

func requireContains(t *testing.T, haystack, needle, why string) {
	t.Helper()
	if !contains(haystack, needle) {
		t.Fatalf("%s: %q is not in:\n%s", why, needle, haystack)
	}
}

// TestTSMGatewayVendorClientReadOnly checks that an access-policy write
// refusal reaches a vendor client as an answer rather than a timeout.
//
// It is a separate test because it needs its own proxy (the policy is
// process-wide), and because a refusal is a *locally generated* response:
// the TSM echo rules apply to it exactly as they do to a forwarded answer,
// and a vendor must be able to tell "denied" from "unreachable".
func TestTSMGatewayVendorClientReadOnly(t *testing.T) {
	requireDockerNetSNMP(t)

	pki := testkit.NewPKIWithNames(t, dockerHost)
	agent := newDevice(t, testkit.AgentOptions{})
	target := startTSMGateway(t, pki, agent, "--read-only")

	home := tsmClientHome(t, pki.ClientCrt, pki.ClientKey, pki.CAFile)

	out, ok := runTSMClient(t, home, "snmpset", "-On", "-v3", "-l", "authPriv",
		"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
		"-t", "5", "-r", "1", target, sysDescr, "s", "must-not-land")
	if ok {
		t.Fatalf("a read-only gateway accepted a SET:\n%s", out)
	}
	requireContains(t, out, "notWritable", "a refused write must reach the vendor as notWritable, not as a timeout")
	if agent.SETs() != 0 {
		t.Fatalf("the refused SET reached the device (%d SETs)", agent.SETs())
	}
}

// startTSMGateway runs the real binary as a tsm-gateway that a container can
// reach (see the package comment on TestTSMGatewayVendorClient) and returns
// the net-snmp `dtls:` target for it.
func startTSMGateway(t *testing.T, pki *testkit.PKI, agent *testkit.Agent, extra ...string) string {
	t.Helper()
	_, port := hostPort(t, testkit.FreeUDPPort(t, "127.0.0.1"))
	args := []string{
		"gateway", "--security", "tsm-gateway",
		"--listen", fmt.Sprintf("[::]:%d", port),
		"--agent", agent.Addr(), "--community", community,
		"--ca-file", pki.CAFile,
		"--cert-file", pki.ServerCrt,
		"--key-file", pki.ServerKey,
	}
	args = append(args, extra...)
	startProxy(t, "tsm-gateway", args...)
	// The port came from a probe, not from a socket the proxy handed us, so
	// wait for the listener: an empty datagram to a closed UDP port is
	// refused, which is enough to tell "not bound yet" from "bound".
	waitFront(t, fmt.Sprintf("127.0.0.1:%d", port))
	return fmt.Sprintf("dtls:%s:%d", dockerHost, port)
}
