// IPv6 scenario for the TSM gateway: the same code on ::1.
//
// The front leg here is a raw DTLS listener, so this is a different set of
// assumptions from the USM gateway's plain-UDP front: the listener address,
// the accepted conn's remote address, the client certificate mapping and the
// outbound clear socket toward the device all have to survive a v6 address.
// (The trap-direction dial and the USM notification sockets are covered by
// internal/usm/ipv6_e2e_test.go; both go through the same tunnel.Dialer.)
//
// Not vendor-driven on purpose: net-snmp needs a `dtls:` target it will
// resolve itself, and the Docker peers can only reach the host over the IPv4
// bridge. Address family is transport, not wire format — see TESTING.md.
package tsm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

func TestTSMGatewayIPv6(t *testing.T) {
	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)

	fake, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	defer fake.Close()
	go agentLoop(fake, nil)

	front, stop := buildTSMGatewayOn(t, "::1", ca, serverCrt, serverKey,
		fake.LocalAddr().String(), []string{"snmp-shield-manager"}, "", "")
	defer stop()
	waitFrontBound(t, front)

	conn := dialFront(t, front, ca, clientCrt, clientKey)
	defer conn.Close()

	if _, err := conn.Write(buildTSMGet(t, 2002, 5150)); err != nil {
		t.Fatalf("write TSM GET over IPv6: %v", err)
	}

	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no TSM response over IPv6 (front listen, clear relay or the response path failed): %v", err)
	}
	m, err := msg.ParseV3(buf[:n])
	if err != nil {
		t.Fatalf("bad response datagram: %v", err)
	}
	if m.Header.SecModel != msg.SecurityModelTSM {
		t.Fatalf("response SecModel = %d, want TSM", m.Header.SecModel)
	}
	if m.Header.MsgID != 2002 {
		t.Fatalf("response msgID = %d, want 2002", m.Header.MsgID)
	}
	if len(m.PDU) == 0 || m.PDU[0] != msg.PDUGetResponse {
		t.Fatalf("response PDU type = %v, want GetResponse", m.PDU)
	}
	if _, fields, err := msg.ParsePDU(m.PDU); err != nil {
		t.Fatalf("bad response PDU: %v", err)
	} else if fields.ReqID != 5150 {
		t.Fatalf("response reqID = %d, want 5150", fields.ReqID)
	}
}
