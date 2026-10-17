// manager_gateway_test.go (package usm_test): end-to-end tests for the
// single-box USM-manager gateway. A gosnmp TrapListener acts as the
// manager's trap receiver (validates our authPriv notifications as an
// independent implementation) and — for informs — answers them like a
// real manager (gosnmp's TrapListener auto-responds to InformRequest
// PDUs with a GetResponse signed with its own keys). Devices send clear
// v1/v2c traps/informs at the gateway's trap listener.
package usm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// buildManagerGateway starts a ManagerGateway listening on trapListen and
// wrapping toward trapSink. Optional trailing filters are passed through.
func buildManagerGateway(t *testing.T, trapListen, trapSink string, filt ...*notifyfilter.Filter) (stop func()) {
	t.Helper()

	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.GatewayRole{
		TrapListenAddr: trapListen,
		TrapSinkAddr:   trapSink,
	}
	users := []usm.Profile{{
		Name:           "proxy",
		AuthProtocol:   usm.AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   usm.PrivAES,
		PrivPassphrase: "privpass",
	}}

	mg, err := usm.NewManagerGateway(cfg, users, clock, zap.NewNop(), nil, filt...)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = mg.Run(done) }()
	return func() { close(done) }
}

// startManagerSink starts a gosnmp TrapListener as the manager's v3 trap
// receiver. Returns the sink address and a channel of received packets.
func startManagerSink(t *testing.T) (string, chan *gosnmp.SnmpPacket) {
	t.Helper()
	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "proxy",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        "privpass",
		},
	}
	trapGot := make(chan *gosnmp.SnmpPacket, 8)
	tl.OnNewTrap = func(s *gosnmp.SnmpPacket, u *net.UDPAddr) {
		trapGot <- s
	}
	sinkAddr := freeUDPPort(t)
	go func() { _ = tl.Listen(sinkAddr) }()
	t.Cleanup(tl.Close)
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener never came up")
	}
	return sinkAddr, trapGot
}

// deviceConn returns a UDP socket for firing clear notifications at the
// gateway's trap listener.
func deviceConn(t *testing.T, trapListen string) net.PacketConn {
	t.Helper()
	laddr, err := net.ResolveUDPAddr("udp", trapListen)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = laddr
	return conn
}

// buildVBS builds a raw varbind-list (SEQUENCE content) with one varbind:
// snmpTrapOID.0 = oid (test helper; BuildPDU takes the raw list content).
func buildVBS(t *testing.T, oid string) []byte {
	t.Helper()
	oidTLV := msg.AppendTLV(nil, 0x06, mustOID(t, oid))
	snmpTrapOIDTLV := msg.AppendTLV(nil, 0x06, msg.OIDSnmpTrapOID)
	return msg.AppendTLV(nil, 0x30, append(append([]byte{}, snmpTrapOIDTLV...), oidTLV...))
}

// TestManagerGatewayTrapRelay: a clear v2c device trap is wrapped into an
// authenticated+encrypted v3 notification and validated by the gosnmp
// TrapListener sink.
func TestManagerGatewayTrapRelay(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildManagerGateway(t, trapListen, sinkAddr)
	defer stop()
	waitBound(t, trapListen)

	vbs := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, buildVBS(t, "1.3.6.1.4.1.9999.1"))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case s := <-trapGot:
		if s.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", s.Version)
		}
		sp, ok := s.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok {
			t.Fatal("no USM security parameters on wrapped trap")
		}
		if sp.UserName != "proxy" {
			t.Fatalf("wrapped trap user = %q, want proxy", sp.UserName)
		}
		if len(s.Variables) == 0 {
			t.Fatal("wrapped trap has no varbinds")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped v3 trap never reached the sink")
	}
}

// TestManagerGatewayInformRoundTrip: a clear v2c device inform is wrapped
// into a v3 inform; the gosnmp TrapListener auto-responds (GetResponse
// signed with the sink's own keys); the gateway verifies/decrypts the
// response and relays a clear v2c response back to the device.
func TestManagerGatewayInformRoundTrip(t *testing.T) {
	sinkAddr, _ := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildManagerGateway(t, trapListen, sinkAddr)
	defer stop()
	waitBound(t, trapListen)

	const reqID = int32(777)
	vbs := msg.BuildPDU(msg.PDUInformRequest, reqID, 0, 0, buildVBS(t, "1.3.6.1.4.1.9999.1"))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	// the clear response must come back to this socket
	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("clear inform response never came back: %v", err)
	}
	ver, community, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("response undecodable: %v", err)
	}
	if ver != msg.Version2c {
		t.Fatalf("response version = %d, want 2c", ver)
	}
	if string(community) != "devicecomm" {
		t.Fatalf("response community = %q, want devicecomm", community)
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("response PDU undecodable: %v", err)
	}
	if pduType != msg.PDUGetResponse {
		t.Fatalf("response PDU type = 0x%02x, want GetResponse", pduType)
	}
	if fields.ReqID != reqID {
		t.Fatalf("response req-id = %d, want %d", fields.ReqID, reqID)
	}
}

// TestManagerGatewayV1Trap: a clear v1 trap is translated (RFC 2576) and
// wrapped like a v2c one.
func TestManagerGatewayV1Trap(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	stop := buildManagerGateway(t, trapListen, sinkAddr)
	defer stop()
	waitBound(t, trapListen)

	trapPDU := msg.BuildV1Trap(msg.V1Trap{
		Enterprise: mustOID(t, "1.3.6.1.4.1.9999"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    0,
		Specific:   0,
		Timestamp:  12345,
		Varbinds:   []byte{},
	})
	dg, err := msg.BuildV1V2c(msg.Version1, []byte("devicecomm"), trapPDU)
	if err != nil {
		t.Fatal(err)
	}
	conn := deviceConn(t, trapListen)
	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	if _, err := conn.WriteTo(dg, laddr); err != nil {
		t.Fatal(err)
	}

	select {
	case s := <-trapGot:
		if s.Version != gosnmp.Version3 {
			t.Fatalf("wrapped trap version = %v, want v3", s.Version)
		}
		if len(s.Variables) == 0 {
			t.Fatal("wrapped v1 trap has no varbinds (v2 translation failed)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrapped v1 trap never reached the sink")
	}
}

// TestManagerGatewayFilter: with a deny filter for an enterprise prefix,
// device traps inside the prefix never reach the sink while traps outside
// it do; the listener stays alive for subsequent traps.
func TestManagerGatewayFilter(t *testing.T) {
	sinkAddr, trapGot := startManagerSink(t)
	trapListen := freeUDPPort(t)
	filt, err := notifyfilter.New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		t.Fatal(err)
	}
	stop := buildManagerGateway(t, trapListen, sinkAddr, filt)
	defer stop()
	waitBound(t, trapListen)

	laddr, _ := net.ResolveUDPAddr("udp", trapListen)
	conn := deviceConn(t, trapListen)
	fire := func(oid string) {
		t.Helper()
		vbs := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, buildVBS(t, oid))
		dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), vbs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(dg, laddr); err != nil {
			t.Fatal(err)
		}
	}

	fire("1.3.6.1.4.1.99.7")  // denied
	fire("1.3.6.1.4.1.999.1") // allowed

	select {
	case <-trapGot:
	case <-time.After(5 * time.Second):
		t.Fatal("allowed trap never reached the sink")
	}
	// drain: no second packet may arrive (the denied one was dropped)
	select {
	case s := <-trapGot:
		t.Fatalf("denied trap reached the sink: %d varbinds", len(s.Variables))
	case <-time.After(700 * time.Millisecond):
	}
	// the listener must still be alive
	fire("1.3.6.1.4.1.999.2")
	select {
	case <-trapGot:
	case <-time.After(5 * time.Second):
		t.Fatal("listener dead after denial")
	}
}
