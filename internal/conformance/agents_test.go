package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// TestUSMGatewayAgents drives the multi-agent gateway shape with every
// independent peer: two front listeners, two distinct fake devices, and
// one config file. A GET through each listener must return that entry's
// device, not the other's.
func TestUSMGatewayAgents(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		devA := testkit.NewAgent(t, testkit.AgentOptions{},
			testkit.Entry{OID: sysDescr, Type: testkit.TagOctetString, Value: []byte("agent-a")})
		devB := testkit.NewAgent(t, testkit.AgentOptions{},
			testkit.Entry{OID: sysDescr, Type: testkit.TagOctetString, Value: []byte("agent-b")})

		bindA, frontA := peerFront(t, p)
		bindB, frontB := peerFront(t, p)
		storeDir := t.TempDir()
		path := filepath.Join(t.TempDir(), "gateway.yaml")
		cfg := fmt.Sprintf(`security:
  mode: usm-gateway
  engine_store_dir: %s
  users:
    - name: %s
      auth_protocol: sha
      auth_passphrase: %s
      priv_protocol: aes
      priv_passphrase: %s
agents:
  - name: a
    listen_addr: %q
    agent_addr: %q
  - name: b
    listen_addr: %q
    agent_addr: %q
`, storeDir, gatewayUsr, authPass, privPass, bindA, devA.Addr(), bindB, devB.Addr())
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}

		proc := startProxy(t, "usm-gateway-agents", "gateway", "--config", path)
		defer proc.Stop(t)
		proc.waitFront(t, frontA)
		proc.waitFront(t, frontB)

		req := func(target, want string) {
			t.Helper()
			res := mustRun(t, p, Request{
				Verb:    VerbGet,
				Version: "3",
				Target:  target,
				User:    gatewayUsr,
				Auth:    authPass,
				Priv:    privPass,
				OIDs:    []string{sysDescr},
				Timeout: 2,
				Retries: 1,
			})
			requireOK(t, res)
			requireVarbind(t, res, sysDescr, "", want)
		}
		req(frontA, "agent-a")
		req(frontB, "agent-b")

		if devA.GETs() == 0 || devB.GETs() == 0 {
			t.Fatalf("not every agent was reached: a=%d b=%d", devA.GETs(), devB.GETs())
		}
	})
}
