package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// TestTSMGatewayAgentsVendorClient drives the multi-agent tsm-gateway
// shape with net-snmp over DTLS: two front listeners, two devices, one
// config file, and the vendor client must reach the right device through
// each listener.
func TestTSMGatewayAgentsVendorClient(t *testing.T) {
	requireDockerNetSNMP(t)

	pki := testkit.NewPKIWithNames(t, dockerHost)
	devA := testkit.NewAgent(t, testkit.AgentOptions{},
		testkit.Entry{OID: sysDescr, Type: testkit.TagOctetString, Value: []byte("agent-a")})
	devB := testkit.NewAgent(t, testkit.AgentOptions{},
		testkit.Entry{OID: sysDescr, Type: testkit.TagOctetString, Value: []byte("agent-b")})

	_, portA := hostPort(t, testkit.FreeUDPPort(t, "127.0.0.1"))
	_, portB := hostPort(t, testkit.FreeUDPPort(t, "127.0.0.1"))
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	cfg := fmt.Sprintf(`security:
  mode: tsm-gateway
tunnel:
  ca_file: %q
  cert_file: %q
  key_file: %q
agents:
  - name: a
    listen_addr: "[::]:%d"
    agent_addr: %q
  - name: b
    listen_addr: "[::]:%d"
    agent_addr: %q
`, pki.CAFile, pki.ServerCrt, pki.ServerKey, portA, devA.Addr(), portB, devB.Addr())
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	proc := startProxy(t, "tsm-gateway-agents", "gateway", "--config", path)
	defer proc.Stop(t)
	proc.waitFront(t, fmt.Sprintf("127.0.0.1:%d", portA))
	proc.waitFront(t, fmt.Sprintf("127.0.0.1:%d", portB))

	home := tsmClientHome(t, pki.ClientCrt, pki.ClientKey, pki.CAFile)
	get := func(port uint16, want string) {
		t.Helper()
		target := fmt.Sprintf("dtls:%s:%d", dockerHost, port)
		out, ok := runTSMClient(t, home, "snmpget", "-On", "-v3", "-l", "authPriv",
			"-u", "manager", "-a", "SHA", "-A", authPass, "-x", "AES", "-X", privPass,
			"-t", "5", "-r", "1", target, sysDescr)
		if !ok {
			t.Fatalf("snmpget through %s failed:\n%s", target, out)
		}
		requireContains(t, out, want, "the wrong device answered through this listener")
	}
	get(portA, "agent-a")
	get(portB, "agent-b")

	if devA.GETs() == 0 || devB.GETs() == 0 {
		t.Fatalf("not every agent was reached: a=%d b=%d", devA.GETs(), devB.GETs())
	}
}
