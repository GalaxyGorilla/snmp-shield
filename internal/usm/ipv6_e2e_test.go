// IPv6 scenarios: the same gateway code paths on ::1 instead of 127.0.0.1.
//
// Why this is a separate file rather than a loop over both hosts in every
// test: the address family is a *deployment* property (an operator with a
// v6-only management LAN), not a behavioural variation. One scenario per
// mode is enough to pin the plumbing — configurally named addresses, the
// outbound sockets, the sink discovery and the trap listener — without
// doubling the runtime of the whole suite.
//
// These are deliberately not vendor-driven: no stack in the matrix can be
// pointed at a v6 loopback port through the peer contract (net-snmp wants a
// `udp6:` URL, and the Docker peers reach the host only by IPv4 bridge
// name). The family is transport, not wire format, so gosnmp plus real
// UDP/TCP sockets is a fair oracle. See TESTING.md.
package usm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// TestGatewayIPv6Request: discovery and an authPriv GET over an IPv6 front
// leg, relayed to a legacy device that also lives on ::1. This is the path
// that binds the clear-agent socket and parses a v3 request from a
// non-loopback-v4 address.
func TestGatewayIPv6Request(t *testing.T) {
	front := freeUDPPortOn(t, "::1")
	agentAddr := freeUDPPortOn(t, "::1")
	agent := newRecAgent(t, agentAddr)
	defer agent.close()

	stop := buildGatewayOn(t, front, agentAddr, "", "")
	defer stop()

	g := gosnmpV3Client(t, front)
	defer g.Conn.Close()

	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("v3 GET over IPv6: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("variables = %d, want 1", len(result.Variables))
	}
	if result.Variables[0].Name != ".1.3.6.1.2.1.1.1.0" {
		t.Fatalf("oid = %q", result.Variables[0].Name)
	}
	if got := len(agent.got); got == 0 {
		t.Fatal("the legacy device never received the forwarded request")
	}
}

// TestGatewayIPv6Inform: a clear inform from an IPv6 device is wrapped,
// delivered to an IPv6 v3 sink, confirmed by that sink, and the clear
// confirmation is returned to the device.
//
// This is the scenario that exercises the sink-discovery socket and the
// trap connection: the notification path has its own outbound sockets, so
// the request-path test above proves nothing about it.
func TestGatewayIPv6Inform(t *testing.T) {
	sinkAddr, _ := startManagerSinkOn(t, "::1")
	trapListen := freeUDPPortOn(t, "::1")
	stop := buildGatewayOn(t, "", "", trapListen, sinkAddr)
	defer stop()

	const reqID = int32(4711)
	pdu := msg.BuildPDU(msg.PDUInformRequest, reqID, 0, 0, buildVBS(t, "1.3.6.1.4.1.9999.9"))
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("devicecomm"), pdu)
	if err != nil {
		t.Fatal(err)
	}

	device := deviceConnOn(t, "::1")
	dst, err := net.ResolveUDPAddr("udp", trapListen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := device.WriteTo(dg, dst); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	_ = device.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := device.ReadFrom(buf)
	if err != nil {
		t.Fatalf("clear inform confirmation never came back over IPv6: %v", err)
	}
	ver, community, rpdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("confirmation undecodable: %v", err)
	}
	if ver != msg.Version2c || string(community) != "devicecomm" {
		t.Fatalf("confirmation = version %d community %q", ver, community)
	}
	typ, fields, err := msg.ParsePDU(rpdu)
	if err != nil {
		t.Fatalf("confirmation PDU undecodable: %v", err)
	}
	if typ != msg.PDUGetResponse || fields.ReqID != reqID {
		t.Fatalf("confirmation = type 0x%02x req-id %d, want GetResponse/%d", typ, fields.ReqID, reqID)
	}
}

// TestManagerGatewayIPv6: the v3 command-generator leg with both the clear
// manager front and the real agent on ::1. Discovery and the request are
// sent from dedicated outbound sockets, so this is a different set of
// address-family assumptions than the USM gateway's.
func TestManagerGatewayIPv6(t *testing.T) {
	front := freeUDPPortOn(t, "::1")
	agent := startFakeV3AgentOn(t, "[::1]:0")
	defer agent.conn.Close()

	_, stop := buildManagerGatewayAt(t, front, agent.addr, "", "")
	defer stop()

	mgr, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	if _, err := mgr.WriteTo(clearGet(t, 4242), mustAddr(t, front)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-agent.saw:
	case <-time.After(5 * time.Second):
		t.Fatal("the v3 agent never saw the forwarded GET (discovery or send failed over IPv6)")
	}

	_ = mgr.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := mgr.ReadFrom(buf)
	if err != nil {
		t.Fatalf("manager read response over IPv6: %v", err)
	}
	if reqID := parseClearResponse(t, buf[:n]); reqID != 4242 {
		t.Fatalf("response req-id = %d, want 4242 (echoed)", reqID)
	}
}
