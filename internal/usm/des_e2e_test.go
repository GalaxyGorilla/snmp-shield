// des_e2e_test.go — the DES privacy protocol on the wire.
//
// AES is what every modern stack negotiates, so every end-to-end scenario in
// this package used AES and `msg.EncryptDES`/`msg.DecryptDES` (RFC 3414
// §8.1.1.1) were reached by no test at all — a legacy protocol kept exactly
// for the old devices that speak nothing else, and therefore never exercised
// against an independent implementation. gosnmp is that implementation here:
// it does its own engine discovery, DES-CBC encryption and zero-padding, so a
// padding or IV mistake on our side shows up as a parse failure rather than
// as a passing self-consistency check.
//
// Two properties are pinned, one per direction:
//   - the REQUEST leg: gosnmp's DES ciphertext must decrypt here (our
//     DecryptDES + the padding that RFC 3414 adds to a block boundary) and
//     our DES response must be accepted by gosnmp;
//   - the NOTIFICATION leg: the v3 trap we wrap with the DES profile must
//     verify and decrypt in a gosnmp TrapListener.
package usm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"github.com/gosnmp/gosnmp"
)

// desUsers is the same profile as defaultGatewayUsers with DES privacy.
func desUsers() []usm.Profile {
	return []usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivDES,
		PrivPassphrase: "privpass",
		Community:      "realcomm",
	}}
}

// desClient builds a gosnmp v3 authPriv client with DES privacy against addr.
func desClient(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	g := &gosnmp.GoSNMP{
		Target:        hostOf(addr),
		Port:          portOf(addr),
		Version:       gosnmp.Version3,
		Timeout:       3 * time.Second,
		Retries:       2,
		MaxOids:       10,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "proxy",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          gosnmp.DES,
			PrivacyPassphrase:        "privpass",
		},
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("gosnmp connect: %v", err)
	}
	return g
}

// TestGatewayDESPrivRequestLeg: discovery + GET over DES-CBC, both directions.
//
// The request's scopedPDU is padded to a block boundary by gosnmp; ours must
// accept the padding and still parse the inner PDU, and our response must be
// padded the same way (gosnmp decrypts and parses it, so a missing pad or a
// wrong pre-IV fails the GET).
func TestGatewayDESPrivRequestLeg(t *testing.T) {
	frontAddr := freeUDPPort(t)
	agentAddr := freeUDPPort(t)

	dev := newRecAgent(t, agentAddr)
	defer dev.close()

	stop := buildGatewayProfiles(t, frontAddr, agentAddr, "", "", desUsers())
	defer stop()

	g := desClient(t, frontAddr)
	defer g.Conn.Close()

	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("DES authPriv GET through gateway: %v", err)
	}
	if len(result.Variables) != 1 || result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("unexpected answer: %+v", result.Variables)
	}

	// And it really was relayed to the device as clear v2c (a DES profile
	// that never reached the back leg would be a fake pass).
	select {
	case <-dev.got:
	case <-time.After(2 * time.Second):
		t.Fatal("the device never saw the relayed request")
	}

	// A second request must work too: the first one also triggers discovery,
	// so it could in principle be answered from a half-initialized state.
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		t.Fatalf("second DES GET: %v", err)
	}
}

// TestGatewayDESPrivTrapLeg: the notification we wrap with a DES profile must
// be verifiable by an independent receiver. A gosnmp TrapListener localizes
// keys to the wire engineID, checks the digest and DES-decrypts the
// scopedPDU, so a padding bug on the notification path fails here too.
func TestGatewayDESPrivTrapLeg(t *testing.T) {
	frontAddr := freeUDPPort(t)
	agentAddr := freeUDPPort(t)
	trapListen := freeUDPPort(t)
	trapSink := freeUDPPort(t)

	dev := newRecAgent(t, agentAddr)
	defer dev.close()

	got := make(chan *gosnmp.SnmpPacket, 4)
	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "proxy",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          gosnmp.DES,
			PrivacyPassphrase:        "privpass",
		},
	}
	tl.OnNewTrap = func(p *gosnmp.SnmpPacket, _ *net.UDPAddr) {
		select {
		case got <- p:
		default:
		}
	}
	go func() { _ = tl.Listen(trapSink) }()
	defer tl.Close()
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener never came up")
	}

	stop := buildGatewayProfiles(t, frontAddr, agentAddr, trapListen, trapSink, desUsers())
	defer stop()

	// A clear v1 coldStart trap at the device-facing ingress becomes a
	// DES-wrapped v3 notification toward the sink.
	trapPDU := msg.BuildV1Trap(msg.V1Trap{
		Enterprise: mustOID(t, "1.3.6.1.4.1.9999"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Timestamp:  12345,
		Varbinds:   []byte{},
	})
	trap, err := msg.BuildV1V2c(msg.Version1, []byte("realcomm"), trapPDU)
	if err != nil {
		t.Fatal(err)
	}
	laddr, err := net.ResolveUDPAddr("udp", trapListen)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo(trap, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case p := <-got:
		if p.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", p.Version)
		}
		sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok {
			t.Fatal("no USM security parameters on the wrapped trap")
		}
		if sp.UserName != "proxy" {
			t.Fatalf("wrapped trap user = %q, want proxy", sp.UserName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no v3 DES trap arrived: the receiver rejected the notification")
	}
}
