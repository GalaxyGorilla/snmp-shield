package proxy

import (
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// reloadCfg builds a valid manager config whose access section varies.
func reloadCfg(a config.Access) *config.Config {
	return &config.Config{
		Role:     config.RoleManager,
		Tunnel:   config.Tunnel{Mode: "dtls", DialAddrs: []string{"10.0.0.1:10162"}, PSK: "text:s"},
		Manager:  config.ManagerRole{ListenAddr: ":161"},
		Security: config.Security{Mode: "passthrough"},
		Access:   a,
	}
}

func setPDUFor(o string) []byte {
	ber, err := msg.EncodeOID(o)
	if err != nil {
		panic(err)
	}
	vb := msg.AppendTLV(nil, 0x06, ber)
	vb = msg.AppendTLV(vb, 0x02, []byte{1})
	return msg.BuildPDU(msg.PDUSetRequest, 1, 0, 0, msg.AppendTLV(nil, 0x30, vb))
}

func TestReloadSwapsAccessPolicy(t *testing.T) {
	cur := reloadCfg(config.Access{})
	h := access.NewHolder(nil)

	// an empty policy allows the write
	curPol, err := cur.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	h.Store(curPol)
	if !h.Get().AllowWrite(setPDUFor("1.3.6.1.4.1.99.1.0")) {
		t.Fatal("initial policy refused a write")
	}

	// reload to read-only: the next datagram must be refused
	next := reloadCfg(config.Access{ReadOnly: true})
	if w := applyReload(cur, next, h); len(w) != 0 {
		t.Fatalf("unexpected warnings: %v", w)
	}
	if h.Get().AllowWrite(setPDUFor("1.3.6.1.4.1.99.1.0")) {
		t.Fatal("reloaded read-only policy did not take effect")
	}

	// and back again
	next = reloadCfg(config.Access{})
	if w := applyReload(cur, next, h); len(w) != 0 {
		t.Fatalf("unexpected warnings: %v", w)
	}
	if !h.Get().AllowWrite(setPDUFor("1.3.6.1.4.1.99.1.0")) {
		t.Fatal("reloaded allow-all policy did not take effect")
	}
}

func TestReloadKeepsPolicyOnInvalidConfig(t *testing.T) {
	cur := reloadCfg(config.Access{ReadOnly: true})
	h := access.NewHolder(nil)
	pol, err := cur.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	h.Store(pol)

	// a broken access section must not silently relax the policy
	next := reloadCfg(config.Access{WritePolicy: &config.WritePolicyCfg{Default: "deny"}})
	w := applyReload(cur, next, h)
	if len(w) == 0 {
		t.Fatal("no warning for an invalid access policy")
	}
	if !h.Get().ReadOnly() {
		t.Fatal("invalid reload replaced the running policy")
	}
}

func TestReloadWarnsOnRestartOnlyChanges(t *testing.T) {
	cur := reloadCfg(config.Access{})
	h := access.NewHolder(nil)

	next := reloadCfg(config.Access{})
	next.Tunnel.DialAddrs = []string{"10.0.0.9:10162"} // listener/endpoint: restart only
	next.Security.Mode = "usm-translate"
	next.Manager.ListenAddr = ":1161"
	next.Notifications.Filter = &config.NotifyFilter{Action: "allow", Oids: []string{"1.3.6.1"}}
	next.Metrics.ListenAddr = "127.0.0.1:9672"

	w := applyReload(cur, next, h)
	want := map[string]bool{
		"tunnel block changed (restart required)":        true,
		"security block changed (restart required)":      true,
		"manager block changed (restart required)":       true,
		"notifications block changed (restart required)": true,
		"metrics block changed (restart required)":       true,
	}
	if len(w) != len(want) {
		t.Fatalf("warnings = %v, want %d", w, len(want))
	}
	for _, m := range w {
		if !want[m] {
			t.Errorf("unexpected warning %q", m)
		}
	}
}

func TestDescribePolicy(t *testing.T) {
	if got := describePolicy(nil); got != "none (allow everything)" {
		t.Errorf("describePolicy(nil) = %q", got)
	}
	c := &config.Config{Access: config.Access{WritePolicy: &config.WritePolicyCfg{
		Default: "deny",
		Rules:   []config.WriteRuleCfg{{OID: "1.3.6.1", Action: "allow"}},
	}}}
	p, err := c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if got := describePolicy(p); got != "read-write, 1 write rules" {
		t.Errorf("describePolicy = %q", got)
	}
}
