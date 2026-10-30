package conformance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snmptrapd_test.go — a third-party v3 notification RECEIVER.
//
// Before this file every "does the manager accept our v3 notification?"
// assertion used internal/testkit.V3Sink, which is written against our own
// msg package. That proves self-consistency at best: if we localize keys,
// boot/time fields or the scoped context engine the same way in the encoder
// and the sink, the test passes and a real manager still drops the trap.
// net-snmp's snmptrapd is the receiving counterpart of the peer matrix and
// has no such symmetry with us.
//
// Two mechanical facts make it work, both learned the hard way:
//
//  1. Traps are sender-authoritative (RFC 3414 §2.2), so snmptrapd has no
//     opportunity to discover the sender's engineID and must be told it in
//     advance: `createUser -e 0x<engineID>`. The fixture therefore pins the
//     proxy's engineID with --engine-id, which is also how HA replicas share
//     one engine — the flag exists for operators, the test just uses it.
//     Informs are receiver-authoritative and would work without the pin;
//     pinning both keeps the fixture symmetric.
//  2. snmptrapd's log is the oracle. It prints one block per notification
//     with `-On` (numeric OIDs), which is exactly enough to assert that the
//     PDU we wrapped arrived with its payload intact.
//
// A trap that snmptrapd rejects leaves NO log line (USM failures are dropped
// in silence per RFC 3414 §4), so every positive assertion here would fail
// loudly on a broken wrap rather than pass vacuously.

// trapdUser is the v3 user the notification-only usm-gateway emits: flags
// mode names its single user "proxy".
const trapdUser = "proxy"

// trapdFixture is a running net-snmp 5.9 snmptrapd in a container, reachable
// on the host at Addr.
type trapdFixture struct {
	Addr string
	name string
}

// startTrapd runs snmptrapd with one USM user registered for engineIDHex
// (the sender's engine, hex without 0x) and returns its host-side address.
func startTrapd(t *testing.T, engineIDHex string) *trapdFixture {
	t.Helper()
	requireDocker(t, "snmptrapd receiver")

	// Let DOCKER pick the host port (-p 127.0.0.1::1162/udp), then ask it
	// what it bound. Probing a free port and publishing it afterwards is a
	// TOCTOU race: the probe closes the socket, docker binds the same number
	// a moment later, and another fixture that probed in that window gets a
	// port that is already taken. That surfaced as "bind: address already in
	// use" on a gateway's trap listener during a full-suite run.
	name := fmt.Sprintf("snmp-shield-trapd-%d-%d", os.Getpid(), time.Now().UnixNano())

	dir := t.TempDir()
	// The user is registered TWICE, because the two notification classes
	// disagree about who is authoritative (RFC 3414 §2.2):
	//   * no -e  → keys localized to the receiver's OWN engine, which is
	//              what a conformant inform needs (receiver-authoritative);
	//   * -e 0x… → keys localized to OUR engine, which is what a trap needs
	//              (sender-authoritative: an unconfirmed notification gives
	//              the receiver no chance to discover the sender).
	// Registering only the -e form makes informs look broken; registering
	// only the default makes every trap invisible.
	conf := fmt.Sprintf(`createUser %s SHA %s AES %s
createUser -e 0x%s %s SHA %s AES %s
authUser log,execute,net %s
disableAuthorization yes
`, trapdUser, authPass, privPass, engineIDHex, trapdUser, authPass, privPass, trapdUser)
	if err := os.WriteFile(filepath.Join(dir, "snmptrapd.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("trapd: write config: %v", err)
	}
	// snmptrapd insists on a writable persistent directory for its app
	// state; the default lives in the image and is read-only in practice.
	if err := os.MkdirAll(filepath.Join(dir, "persist"), 0o777); err != nil {
		t.Fatalf("trapd: persist dir: %v", err)
	}

	_ = exec.Command("docker", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-p", "127.0.0.1::1162/udp",
		"-v", dir+":/cfg",
		"-v", filepath.Join(dir, "persist")+":/var/lib/snmp",
		dockerNetSNMPImage,
		"snmptrapd", "-f", "-Lo", "-On", "-c", "/cfg/snmptrapd.conf", "udp:1162",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("trapd: docker run: %v (%s)", err, firstLine(string(out)))
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	pubOut, err := exec.Command("docker", "port", name, "1162/udp").Output()
	if err != nil {
		t.Fatalf("trapd: docker port: %v", err)
	}
	hostPort := publishedLoopback(t, strings.TrimSpace(string(pubOut)))

	f := &trapdFixture{Addr: hostPort, name: name}
	f.waitReady(t)
	return f
}

// publishedLoopback picks the 127.0.0.1 entry out of `docker port` output
// (it prints one line per address family) and fails loudly when the mapping
// is missing entirely — an empty mapping would silently send notifications
// into the void and turn every assertion into a timeout.
func publishedLoopback(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "127.0.0.1:") {
			return line
		}
	}
	t.Fatalf("trapd: docker port printed no 127.0.0.1 mapping (%q)", out)
	return ""
}

// waitReady blocks until snmptrapd announced itself. A container whose
// config was rejected exits immediately, so that is distinguished from a
// slow start.
func (f *trapdFixture) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(f.logs(), "NET-SNMP version") {
			return
		}
		if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", f.name).Output(); err == nil &&
			strings.TrimSpace(string(out)) == "false" {
			t.Fatalf("trapd exited during startup:\n%s", f.logs())
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("trapd did not become ready:\n%s", f.logs())
}

func (f *trapdFixture) logs() string {
	out, _ := exec.Command("docker", "logs", f.name).CombinedOutput()
	return string(out)
}

// waitForLog polls the receiver's log until it contains want (the whole log
// is returned so the failure message can show what actually arrived).
func (f *trapdFixture) waitForLog(t *testing.T, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var logs string
	for time.Now().Before(deadline) {
		logs = f.logs()
		if strings.Contains(logs, want) {
			return logs
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("snmptrapd never logged %q within %s; receiver log:\n%s", want, timeout, logs)
	return logs
}

// requireDocker skips when there is no usable Docker daemon or image.
func requireDocker(t *testing.T, what string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		skipOrFail(t, "%s unavailable: docker not installed (run `make peers`)", what)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		skipOrFail(t, "%s unavailable: docker daemon not reachable (%s)", what, firstLine(string(out)))
	}
	if err := exec.Command("docker", "image", "inspect", dockerNetSNMPImage).Run(); err != nil {
		skipOrFail(t, "%s unavailable: image %s missing (run `make peers`)", what, dockerNetSNMPImage)
	}
}

// startNotifyGateway runs the notification-only usm-gateway shape with a
// pinned engineID (so the receiver can have the user registered in advance)
// and returns the trap listener address a sender dials.
func startNotifyGateway(t *testing.T, p Peer, engineIDHex, sinkAddr string) (trapAddr string) {
	t.Helper()
	bindTrap, trapAddr := peerFront(t, p)
	proc := startProxy(t, "usm-gateway-notify",
		"gateway", "--security", "usm-gateway",
		"--trap-listen", bindTrap, "--trap-sink", sinkAddr,
		"--auth-pass", authPass, "--priv-pass", privPass,
		"--engine-id", engineIDHex,
		"--engine-store", filepath.Join(t.TempDir(), "engine.json"),
	)
	proc.waitFront(t, trapAddr)
	return trapAddr
}

// TestUSMGatewayVendorTrapReceiver drives a clear v2c trap through the
// gateway and asserts a real snmptrapd accepted and logged it: digest
// verified, decrypted, payload intact.
func TestUSMGatewayVendorTrapReceiver(t *testing.T) {
	const engineID = "800000000000000000000001"
	trapd := startTrapd(t, engineID)

	eachPeer(t, func(t *testing.T, p Peer) {
		trapAddr := startNotifyGateway(t, p, engineID, trapd.Addr)
		// A per-peer OID keeps the receiver's cumulative log unambiguous
		// even if a previous peer's notification arrives late.
		trapOID := "1.3.6.1.4.1.99." + peerOIDArc(p) + ".1"
		payloadOID := "1.3.6.1.4.1.99." + peerOIDArc(p) + ".2.0"
		payload := "payload-" + p.Name()

		res := mustRun(t, p, Request{
			Verb: VerbTrap, Version: "2c", Community: community,
			Target: trapAddr, OIDs: []string{trapOID},
			Varbinds: []string{payloadOID + "=string:" + payload},
			Timeout:  2,
		})
		skipUnsupported(t, res)
		requireOK(t, res)

		// The receiver logs `snmpTrapOID.0 = OID: <trapOID>` and the
		// payload varbind on the same block.
		logs := trapd.waitForLog(t, "OID: ."+trapOID, 15*time.Second)
		if !strings.Contains(logs, `STRING: "`+payload+`"`) {
			t.Fatalf("snmptrapd received the trap but not its payload %q; receiver log:\n%s", payload, logs)
		}
	})
}

// TestUSMGatewayVendorInformReceiver is the confirmed-notification direction:
// the device's v2c inform is wrapped as a v3 inform, and the CONFIRMATION the
// vendor sends back has to satisfy the device's snmpinform. A proxy that
// wrapped informs but never relayed the answer would leave the device
// retransmitting until it timed out (the exact bug this repository hit in
// three separate modes), and the vendor's own exit status catches it.
func TestUSMGatewayVendorInformReceiver(t *testing.T) {
	const engineID = "800000000000000000000002"
	trapd := startTrapd(t, engineID)

	eachPeer(t, func(t *testing.T, p Peer) {
		trapAddr := startNotifyGateway(t, p, engineID, trapd.Addr)
		arc := peerOIDArc(p)
		payload := "inform-" + p.Name()

		res := mustRun(t, p, Request{
			Verb: VerbInform, Version: "2c", Community: community,
			Target: trapAddr, OIDs: []string{"1.3.6.1.4.1.98." + arc + ".1"},
			Varbinds: []string{"1.3.6.1.4.1.98." + arc + ".2.0=string:" + payload},
			Timeout:  3, Retries: 1,
		})
		skipUnsupported(t, res)
		// OK means the sender received its confirmation: the vendor's
		// snmpinform exited 0, so the answer travelled back through our
		// pending-inform map to the device.
		requireOK(t, res)

		logs := trapd.waitForLog(t, `STRING: "`+payload+`"`, 15*time.Second)
		if !strings.Contains(logs, "OID: .1.3.6.1.4.1.98."+arc+".1") {
			t.Fatalf("snmptrapd logged the inform payload without its trap OID; receiver log:\n%s", logs)
		}
	})
}

// peerOIDArc maps a peer to a distinct OID arc so parallel/sequential peers
// cannot be confused in a shared receiver log.
func peerOIDArc(p Peer) string {
	switch p.Name() {
	case "gosnmp":
		return "11"
	case "netsnmp":
		return "12"
	case "pysnmp":
		return "13"
	case "node":
		return "14"
	case "netsnmp59":
		return "15"
	}
	return "19"
}
