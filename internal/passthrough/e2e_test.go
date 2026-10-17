package passthrough_test

// End-to-end test: gosnmp manager client -> manager-side proxy ->
// PSK-DTLS tunnel -> agent-side proxy -> fake Go SNMP agent, on
// loopback. Also exercises the device->manager trap path.
//
// The fake agent answers GET 1.3.6.1.2.1.1.1.0 (sysDescr) with a
// hand-built v2c RESPONSE so no net-snmp dependency is needed.

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/passthrough"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// buildV2cResponse builds a minimal v2c GetResponse PDU datagram.
func buildV2cResponse(reqID int32, oid string, value string) []byte {
	// varbind: SEQUENCE { OID, OCTET STRING }
	oidBytes := encodeOID(oid)
	oidTLV := append([]byte{0x06, byte(len(oidBytes))}, oidBytes...)
	valBytes := []byte(value)
	valTLV := append([]byte{0x04}, append(lenPrefix(len(valBytes)), valBytes...)...)
	vb := append([]byte{0x30}, append(lenPrefix(len(oidTLV)+len(valTLV)), append(oidTLV, valTLV...)...)...)
	vbSeq := append([]byte{0x30}, append(lenPrefix(len(vb)), vb...)...)

	pduBody := []byte{}
	req := make([]byte, 4)
	binary.BigEndian.PutUint32(req, uint32(reqID))
	pduBody = append(pduBody, 0x02, 0x04)
	pduBody = append(pduBody, req...)
	pduBody = append(pduBody, 0x02, 0x01, 0x00) // error-status = 0
	pduBody = append(pduBody, 0x02, 0x01, 0x00) // error-index = 0
	pduBody = append(pduBody, vbSeq...)
	pdu := append([]byte{0xA2}, append(lenPrefix(len(pduBody)), pduBody...)...)

	ver := []byte{0x02, 0x01, 0x01} // v2c
	comm := append([]byte{0x04}, append(lenPrefix(len("public")), []byte("public")...)...)
	body := append(append(ver, comm...), pdu...)
	return append([]byte{0x30}, append(lenPrefix(len(body)), body...)...)
}

func lenPrefix(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xFF {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n & 0xFF)}
}

// encodeOID encodes a dotted OID string into BER content bytes.
func encodeOID(dotted string) []byte {
	parts := []byte{}
	cur := 0
	d := dotted + "."
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			parts = append(parts, byte(cur))
			cur = 0
		} else {
			cur = cur*10 + int(d[i]-'0')
		}
	}
	// first two arcs encoded as 40*a+b; here 1.3 -> 43
	out := []byte{parts[0]*40 + parts[1]}
	out = append(out, parts[2:]...)
	return out
}

// fakeAgent answers v2c GETs on a UDP socket.
func fakeAgent(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake agent listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Build a response echoing the request-id from the request.
			// Request-id is the first INTEGER after the PDU tag+len;
			// for our gosnmp GET (community "public", v2c) we locate it
			// by parsing: SEQUENCE, INTEGER ver, OCTET STRING comm, PDU.
			reqID := extractReqID(buf[:n])
			resp := buildV2cResponse(reqID, "1.3.6.1.2.1.1.1.0", "fake-agent v1")
			_, _ = conn.WriteToUDP(resp, addr)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// extractReqID finds the request-id INTEGER in a v1/v2c request using
// the shared msg Peek parser (gosnmp encodes request-ids minimally, so
// hand-rolled fixed-width parsing does not work).
func extractReqID(data []byte) int32 {
	info, err := msg.Peek(data)
	if err != nil {
		return 0
	}
	return info.RequestID
}

// startProxies wires manager+agent proxy instances over a PSK-DTLS
// loopback tunnel and returns the manager clear-listen address.
func startProxies(t *testing.T) net.Addr {
	t.Helper()
	log := zap.NewNop()
	met := observ.NewMetrics()

	agent := fakeAgent(t)
	agentAddr := agent.LocalAddr().String()

	// Tunnel: agent side listens, manager dials.
	psk := []byte("e2e-test-psk")
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode:        "dtls",
		PSK:         psk,
		PSKIdentity: []byte("e2e"),
	})
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	acceptDone := make(chan *tunnel.Session, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		sess := tunnel.NewServerSession(conn, 65536, 1200, log)
		agt := passthrough.NewAgent(config.AgentRole{AgentAddr: agentAddr}, sess, log, met)
		go agt.Run(context.Background())
		acceptDone <- sess
	}()

	dial := &tunnel.Dialer{
		Mode:        "dtls",
		RemoteAddr:  l.Addr().String(),
		PSK:         psk,
		PSKIdentity: []byte("e2e"),
		Timeout:     5 * time.Second,
	}
	sess := tunnel.NewClientSession(dial, 65536, 1200, log)
	t.Cleanup(func() { sess.Close() })
	if err := sess.Connect(context.Background()); err != nil {
		t.Fatalf("tunnel connect: %v", err)
	}

	// Manager-side clear listener: Manager owns its own socket on a free
	// port (bind probe, close, use).
	mgrAddr := freeUDPPort(t)
	mgr := passthrough.NewManager(config.ManagerRole{ListenAddr: mgrAddr}, sess, log, met)
	go mgr.Run(context.Background())
	t.Cleanup(mgr.Close)
	time.Sleep(100 * time.Millisecond)

	// Wait for the agent side to accept.
	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel handshake timeout")
	}
	saddr, _ := net.ResolveUDPAddr("udp", mgrAddr)
	return saddr
}

func TestEndToEndGet(t *testing.T) {
	mgrAddr := startProxies(t)

	g := &gosnmp.GoSNMP{
		Target:             hostOf(mgrAddr.String()),
		Port:               portOf(mgrAddr.String()),
		Community:          "public",
		Version:            gosnmp.Version2c,
		Timeout:            5 * time.Second,
		Retries:            2,
		MaxOids:            1,
		Transport:          "udp",
		ExponentialTimeout: true,
	}
	err := g.Connect()
	if err != nil {
		t.Fatalf("gosnmp connect: %v", err)
	}
	defer g.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := g.Get(oids)
	if err != nil {
		t.Fatalf("gosnmp get through tunnel: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("want 1 varbind, got %d", len(result.Variables))
	}
	v := result.Variables[0]
	if v.Type != gosnmp.OctetString {
		t.Fatalf("want OctetString, got %v", v.Type)
	}
	if !bytes.Contains(v.Value.([]byte), []byte("fake-agent")) {
		t.Fatalf("unexpected value: %q", v.Value)
	}
}

func TestEndToEndMultipleGets(t *testing.T) {
	mgrAddr := startProxies(t)

	g := &gosnmp.GoSNMP{
		Target:    hostOf(mgrAddr.String()),
		Port:      portOf(mgrAddr.String()),
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   2,
		MaxOids:   1,
		Transport: "udp",
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer g.Conn.Close()

	for i := 0; i < 5; i++ {
		if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
			t.Fatalf("iteration %d: get failed: %v", i, err)
		}
	}
}

// TestEndToEndTrapPath exercises device -> agent-side proxy -> tunnel ->
// manager-side proxy -> trap sink with a raw datagram.
func TestEndToEndTrapPath(t *testing.T) {
	log := zap.NewNop()
	met := observ.NewMetrics()

	// Trap sink on the manager side.
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	defer sink.Close()
	sinkCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			sinkCh <- b
		}
	}()

	psk := []byte("e2e-trap-psk")
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("e2e"),
	})
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	defer l.Close()

	// Agent side with a FIXED trap listener port (probe-bind-close) so
	// the device socket below can send to it.
	trapPort := freeUDPPort(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		sess := tunnel.NewServerSession(conn, 65536, 1200, log)
		// Real trap path: device -> agent-side trap listener -> tunnel
		// NOTIF -> manager-side sink.
		agt := passthrough.NewAgent(config.AgentRole{AgentAddr: "127.0.0.1:1", TrapListenAddr: trapPort}, sess, log, met)
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

	// Manager owns its clear listener on a free port; NOTIF frames
	// arriving over the tunnel are delivered to the trap sink.
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
	case <-time.After(100 * time.Millisecond):
	}

	// Device sends a trap datagram to the agent-side clear trap listener.
	trap := buildV2cResponse(0, "1.3.6.1.6.3.1.1.5.1", "cold-start")
	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", trapPort)
	if _, err := device.WriteToUDP(trap, taddr); err != nil {
		t.Fatalf("device send: %v", err)
	}

	select {
	case got := <-sinkCh:
		if !bytes.Equal(got, trap) {
			t.Fatalf("sink got %d bytes, want %d identical bytes", len(got), len(trap))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trap did not reach sink in time")
	}
}

// mustBuildV2cTrap builds a v2c trap datagram whose first varbind is
// snmpTrapOID.0 (unlike buildV2cResponse, which is a GetResponse).
func mustBuildV2cTrap(t *testing.T, trapOID string) []byte {
	t.Helper()
	oidBer, err := msg.EncodeOID(trapOID)
	if err != nil {
		t.Fatalf("EncodeOID(%q): %v", trapOID, err)
	}
	oidTLV := msg.AppendTLV(nil, 0x06, oidBer)
	snmpTrapOIDTLV := msg.AppendTLV(nil, 0x06, msg.OIDSnmpTrapOID)
	vb1 := msg.AppendTLV(nil, 0x30, append(append([]byte{}, snmpTrapOIDTLV...), oidTLV...))
	pdu := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vb1)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatalf("BuildV1V2c: %v", err)
	}
	return dg
}

// TestEndToEndTrapFilter exercises the notification filter on the
// agent-side relay: an allowed trap reaches the sink, a denied trap does
// not, and the listener stays alive for a subsequent allowed trap.
func TestEndToEndTrapFilter(t *testing.T) {
	log := zap.NewNop()
	met := observ.NewMetrics()

	filt, err := notifyfilter.New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		t.Fatal(err)
	}

	// Trap sink on the manager side.
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	defer sink.Close()
	sinkCh := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			sinkCh <- b
		}
	}()

	psk := []byte("e2e-trap-filter-psk")
	l, err := tunnel.Listen("127.0.0.1:0", tunnel.ListenerConfig{
		Mode: "dtls", PSK: psk, PSKIdentity: []byte("e2e"),
	})
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	defer l.Close()

	trapPort := freeUDPPort(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		sess := tunnel.NewServerSession(conn, 65536, 1200, log)
		agt := passthrough.NewAgent(config.AgentRole{AgentAddr: "127.0.0.1:1", TrapListenAddr: trapPort}, sess, log, met, filt)
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
	case <-time.After(100 * time.Millisecond):
	}

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	taddr, _ := net.ResolveUDPAddr("udp", trapPort)

	// 1. Allowed trap arrives at the sink.
	allowed := mustBuildV2cTrap(t, "1.3.6.1.4.1.999")
	if _, err := device.WriteToUDP(allowed, taddr); err != nil {
		t.Fatalf("device send (allowed): %v", err)
	}
	select {
	case got := <-sinkCh:
		if !bytes.Equal(got, allowed) {
			t.Fatalf("sink got %d bytes, want %d identical bytes", len(got), len(allowed))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("allowed trap did not reach sink in time")
	}

	// 2. Denied trap never arrives.
	denied := mustBuildV2cTrap(t, "1.3.6.1.4.1.99.5")
	if _, err := device.WriteToUDP(denied, taddr); err != nil {
		t.Fatalf("device send (denied): %v", err)
	}
	// 3. A second allowed trap arrives (proves the listener survived).
	allowed2 := mustBuildV2cTrap(t, "1.3.6.1.4.1.999.1")
	if _, err := device.WriteToUDP(allowed2, taddr); err != nil {
		t.Fatalf("device send (allowed2): %v", err)
	}

	drain := time.After(700 * time.Millisecond)
	gotDenied := false
	gotAllowed2 := false
	for !gotAllowed2 {
		select {
		case got := <-sinkCh:
			if bytes.Equal(got, denied) {
				gotDenied = true
				t.Error("denied trap reached the sink")
			} else if bytes.Equal(got, allowed2) {
				gotAllowed2 = true
			}
		case <-drain:
			t.Fatal("second allowed trap did not reach sink (listener broken?)")
		}
	}
	if gotDenied {
		t.Fatal("denied trap was forwarded")
	}
}

// freeUDPPort returns a free loopback UDP port (binds and closes).
func freeUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func portOf(addr string) uint16 {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return uint16(n)
}
