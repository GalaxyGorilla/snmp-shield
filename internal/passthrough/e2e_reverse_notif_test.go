// e2e_reverse_notif_test.go — the notification direction the passthrough
// tunnel was missing: a clear notification arriving at the MANAGER-side trap
// listener must cross the tunnel and be delivered at the AGENT-side trap sink.
//
// The other direction (agent-side device → manager sink) was covered; this one
// was not, and it did not work at all: `Manager.serveClearTraps` shipped NOTIF
// frames that the agent side never subscribed to, so `manager.trap_listen_addr`
// accepted notifications and silently dropped every one of them (and
// `agent.trap_sink_addr`, documented as the sink for tunnel notifications, was
// dead in passthrough mode). A dropped trap is the worst failure shape for
// monitoring: nothing errors, the event simply never exists.
//
// Informs are the reason this cannot be a one-liner: the device expects a
// confirmation, and an unconfirmed inform is retransmitted until the device
// gives up. The confirmation must come from the socket that received the
// inform (connected UDP senders drop anything else).
package passthrough_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/passthrough"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/gosnmp/gosnmp"
	"go.uber.org/zap"
)

// reverseChain wires a manager side that owns a clear trap listener and an
// agent side that owns a trap sink, over a real PSK-DTLS tunnel.
type reverseChain struct {
	trapListen string
	sink       *net.UDPConn
	sinkCh     chan []byte
}

func startReverseChain(t *testing.T) *reverseChain {
	t.Helper()
	log := zap.NewNop()
	met := observ.NewMetrics()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	t.Cleanup(func() { sink.Close() })
	sinkCh := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, rerr := sink.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			sinkCh <- b
		}
	}()

	psk := []byte("reverse-notif-psk")
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("e2e"),
	})
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	trapListen := freeUDPPort(t)
	go func() {
		conn, aerr := l.Accept()
		if aerr != nil {
			return
		}
		sess := tunnel.NewServerSession(conn, 65536, 1200, log)
		agt := passthrough.NewAgent(config.AgentRole{
			AgentAddr:    "127.0.0.1:1",
			TrapSinkAddr: sink.LocalAddr().String(),
		}, sess, log, met)
		_ = agt.Run(context.Background())
	}()

	dial := &tunnel.Dialer{
		Mode: "dtls", RemoteAddr: l.Addr().String(),
		PSK: psk, PSKIdentity: []byte("e2e"), Timeout: 5 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, 65536, 1200, log)
	t.Cleanup(func() { sess.Close() })
	if err := sess.Connect(context.Background()); err != nil {
		t.Fatalf("tunnel connect: %v", err)
	}

	mgr := passthrough.NewManager(config.ManagerRole{
		ListenAddr:     freeUDPPort(t),
		TrapListenAddr: trapListen,
	}, sess, log, met)
	mgrErr := make(chan error, 1)
	go func() { mgrErr <- mgr.Run(context.Background()) }()
	t.Cleanup(mgr.Close)
	select {
	case err := <-mgrErr:
		t.Fatalf("manager exited: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	return &reverseChain{trapListen: trapListen, sink: sink, sinkCh: sinkCh}
}

// TestEndToEndTrapFromManagerSide: a clear trap accepted on the manager side
// arrives at the agent-side sink byte for byte (passthrough must not rewrite
// what it forwards).
func TestEndToEndTrapFromManagerSide(t *testing.T) {
	ch := startReverseChain(t)

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", ch.trapListen)

	trap := mustBuildV2cTrap(t, "1.3.6.1.4.1.999.42")
	if _, err := device.WriteToUDP(trap, taddr); err != nil {
		t.Fatalf("device send: %v", err)
	}
	select {
	case got := <-ch.sinkCh:
		if !bytes.Equal(got, trap) {
			t.Fatalf("sink got %d bytes, want the %d sent bytes unchanged", len(got), len(trap))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a trap accepted on the manager side never reached the agent-side sink")
	}
}

// TestEndToEndManagerIngressRejectsNonNotifications: the manager-side trap
// listener accepts notifications only. Passthrough forwards bytes without
// parsing them again, so a GetResponse that lands on the trap port (a
// misdirected request, a port probe, a scanner) would otherwise be delivered
// to the far-side sink as if the device had fired an event — and the sink has
// no way to tell the difference.
func TestEndToEndManagerIngressRejectsNonNotifications(t *testing.T) {
	ch := startReverseChain(t)

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", ch.trapListen)

	if _, err := device.WriteToUDP(buildV2cResponse(7, "1.3.6.1.2.1.1.1.0", "not-a-notification"), taddr); err != nil {
		t.Fatalf("device send: %v", err)
	}
	select {
	case got := <-ch.sinkCh:
		t.Fatalf("a non-notification datagram (%d bytes) was relayed to the sink as a notification", len(got))
	case <-time.After(300 * time.Millisecond):
	}

	// The listener must keep serving after the refusal.
	trap := mustBuildV2cTrap(t, "1.3.6.1.4.1.999.43")
	if _, err := device.WriteToUDP(trap, taddr); err != nil {
		t.Fatalf("device send (trap): %v", err)
	}
	select {
	case got := <-ch.sinkCh:
		if !bytes.Equal(got, trap) {
			t.Fatalf("sink got %d bytes, want the %d sent bytes unchanged", len(got), len(trap))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the manager-side trap listener stopped relaying after a non-notification datagram")
	}
}

// TestEndToEndInformFromManagerSide: the same path for an INFORM, which must
// additionally be confirmed to the device — with the inform's own request-id,
// from the trap listener's address.
func TestEndToEndInformFromManagerSide(t *testing.T) {
	ch := startReverseChain(t)

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", ch.trapListen)

	const reqID = 4242
	inform := mustBuildV2cInform(t, "1.3.6.1.4.1.999.7", reqID)
	if _, err := device.WriteToUDP(inform, taddr); err != nil {
		t.Fatalf("device send: %v", err)
	}

	select {
	case got := <-ch.sinkCh:
		if !bytes.Equal(got, inform) {
			t.Fatalf("sink got %d bytes, want the %d sent bytes unchanged", len(got), len(inform))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an inform accepted on the manager side never reached the agent-side sink")
	}

	buf := make([]byte, 65536)
	_ = device.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := device.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no confirmation for the inform: %v (the device would retransmit forever)", err)
	}
	// The answer must come from the socket the inform was sent to: a
	// connected sender (gosnmp, net-snmp's default) drops anything else.
	if from.String() != ch.trapListen {
		t.Fatalf("confirmation came from %s, want the trap listener %s", from, ch.trapListen)
	}
	ver, community, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("confirmation is not a v1/v2c datagram: %v", err)
	}
	if ver != msg.Version2c || string(community) != "public" {
		t.Fatalf("confirmation version/community = %d/%q, want v2c/public", ver, community)
	}
	typ, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("confirmation PDU: %v", err)
	}
	if typ != msg.PDUGetResponse {
		t.Fatalf("confirmation PDU type = %#x, want GetResponse", typ)
	}
	if fields.ReqID != reqID {
		t.Fatalf("confirmation request-id = %d, want the inform's %d", fields.ReqID, reqID)
	}
	if fields.ErrStatus != 0 {
		t.Fatalf("confirmation error-status = %d, want 0", fields.ErrStatus)
	}
}

// TestEndToEndInformFromAgentSide pins the confirmation for the direction that
// was already "working": a device inform at the AGENT-side trap listener
// reached the manager's sink, and that was the whole story — the manager never
// answered the NOTIF, the agent's `awaitInformResp` waited out its 15s timer,
// and the device retransmitted until it gave up. Bookkeeping theater, the same
// shape as the USM and TSM inform bugs.
func TestEndToEndInformFromAgentSide(t *testing.T) {
	log := zap.NewNop()
	met := observ.NewMetrics()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	defer sink.Close()
	sinkCh := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, rerr := sink.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			sinkCh <- b
		}
	}()

	psk := []byte("agent-side-inform-psk")
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("e2e"),
	})
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	defer l.Close()

	trapListen := freeUDPPort(t)
	go func() {
		conn, aerr := l.Accept()
		if aerr != nil {
			return
		}
		sess := tunnel.NewServerSession(conn, 65536, 1200, log)
		agt := passthrough.NewAgent(config.AgentRole{
			AgentAddr:      "127.0.0.1:1",
			TrapListenAddr: trapListen,
		}, sess, log, met)
		_ = agt.Run(context.Background())
	}()

	dial := &tunnel.Dialer{
		Mode: "dtls", RemoteAddr: l.Addr().String(),
		PSK: psk, PSKIdentity: []byte("e2e"), Timeout: 5 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, 65536, 1200, log)
	defer sess.Close()
	if err := sess.Connect(context.Background()); err != nil {
		t.Fatalf("tunnel connect: %v", err)
	}

	mgr := passthrough.NewManager(config.ManagerRole{
		ListenAddr:   freeUDPPort(t),
		TrapSinkAddr: sink.LocalAddr().String(),
	}, sess, log, met)
	mgrErr := make(chan error, 1)
	go func() { mgrErr <- mgr.Run(context.Background()) }()
	defer mgr.Close()
	select {
	case err := <-mgrErr:
		t.Fatalf("manager exited: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", trapListen)

	const reqID = 7777
	inform := mustBuildV2cInform(t, "1.3.6.1.4.1.999.8", reqID)
	if _, err := device.WriteToUDP(inform, taddr); err != nil {
		t.Fatalf("device send: %v", err)
	}

	select {
	case got := <-sinkCh:
		if !bytes.Equal(got, inform) {
			t.Fatalf("sink got %d bytes, want the %d sent bytes unchanged", len(got), len(inform))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the inform never reached the manager-side sink")
	}

	buf := make([]byte, 65536)
	_ = device.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := device.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no confirmation for the agent-side inform: %v (the device would retransmit forever)", err)
	}
	if from.String() != trapListen {
		t.Fatalf("confirmation came from %s, want the trap listener %s", from, trapListen)
	}
	_, _, pdu, err := msg.SplitV1V2c(buf[:n])
	if err != nil {
		t.Fatalf("confirmation is not a v1/v2c datagram: %v", err)
	}
	typ, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("confirmation PDU: %v", err)
	}
	if typ != msg.PDUGetResponse || fields.ReqID != reqID || fields.ErrStatus != 0 {
		t.Fatalf("confirmation = type %#x reqID %d status %d, want GetResponse/%d/0",
			typ, fields.ReqID, fields.ErrStatus, reqID)
	}
}

// TestEndToEndInformConfirmedToGosnmp is the same property judged by an
// independent stack: gosnmp sends a v2c inform and waits for its confirmation
// on a CONNECTED socket, so it fails if the answer carries the wrong
// request-id, the wrong community, a non-zero error-status or arrives from a
// different source port. Our own parser would accept all four.
func TestEndToEndInformConfirmedToGosnmp(t *testing.T) {
	ch := startReverseChain(t)

	host, portStr, err := net.SplitHostPort(ch.trapListen)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Transport: "udp",
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   3 * time.Second,
		Retries:   0,
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("gosnmp connect: %v", err)
	}
	defer g.Conn.Close()

	_, err = g.SendTrap(gosnmp.SnmpTrap{
		IsInform: true,
		Variables: []gosnmp.SnmpPDU{{
			Name:  ".1.3.6.1.6.3.1.1.4.1.0",
			Type:  gosnmp.ObjectIdentifier,
			Value: "1.3.6.1.4.1.999.9",
		}},
	})
	if err != nil {
		t.Fatalf("gosnmp did not accept our inform confirmation: %v", err)
	}

	// The confirmation is only meaningful if the notification was delivered.
	select {
	case got := <-ch.sinkCh:
		if oid, ok := msg.TrapOID(got); !ok || oid != "1.3.6.1.4.1.999.9" {
			t.Fatalf("sink got trap OID %q (ok=%v), want 1.3.6.1.4.1.999.9", oid, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the inform was confirmed but never reached the agent-side sink")
	}
}

// mustBuildV2cInform builds a v2c inform whose snmpTrapOID.0 varbind names
// trapOID, with the given request-id.
func mustBuildV2cInform(t *testing.T, trapOID string, reqID int32) []byte {
	t.Helper()
	oidBer, err := msg.EncodeOID(trapOID)
	if err != nil {
		t.Fatalf("EncodeOID(%q): %v", trapOID, err)
	}
	vb := msg.AppendTLV(nil, 0x30, append(
		msg.AppendTLV(nil, 0x06, msg.OIDSnmpTrapOID),
		msg.AppendTLV(nil, 0x06, oidBer)...))
	pdu := msg.BuildPDU(msg.PDUInformRequest, reqID, 0, 0, vb)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatalf("BuildV1V2c: %v", err)
	}
	return dg
}
