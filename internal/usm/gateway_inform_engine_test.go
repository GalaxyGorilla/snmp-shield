// gateway_inform_engine_test.go — which engine is authoritative for a
// notification, pinned on the wire.
//
// RFC 3414 §2.2 splits the two notification classes:
//
//	trap    → the SENDER is authoritative: the message names our engine and
//	          the receiver localizes the user's keys to it.
//	inform  → the RECEIVER is authoritative: the sender must discover the
//	          receiver's engine first and localize keys to THAT.
//
// Getting this backwards is invisible to lenient receivers (gosnmp's
// TrapListener and our own testkit sink both derive keys from whatever
// engineID the message carries, so they accept either form). net-snmp's
// snmptrapd is strict: it answers an inform only when the message is
// addressed to its own engine, and otherwise drops it in silence — the
// device then retransmits into a timeout. The conformance matrix caught it;
// this test pins the fix without Docker, so a regression fails here first.
package usm

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"go.uber.org/zap"
)

// sinkEngine is the fake receiver's engine, deliberately different from the
// gateway's generated one.
var sinkEngine = []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa}

const (
	sinkBoots = uint32(7)
	sinkTime  = uint32(123)
)

// fakeAuthoritativeSink answers one discovery probe with a Report for its
// own engine and then hands back the next datagram it receives.
func fakeAuthoritativeSink(t *testing.T) (addr string, next func(t *testing.T) []byte, probes func() int) {
	t.Helper()
	return fakeAuthoritativeSinkOn(t, "127.0.0.1:0")
}

// fakeAuthoritativeSinkOn binds the receiver on an explicit address, so the
// discovery path can be exercised in the address family an operator
// actually deploys (the notification sockets are separate from the
// request-path sockets, so the USM gateway's IPv6 request test proves
// nothing about them).
func fakeAuthoritativeSinkOn(t *testing.T, bind string) (addr string, next func(t *testing.T) []byte, probes func() int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", bind)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	probeCount := make(chan int, 8)
	inbox := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			dg := append([]byte{}, buf[:n]...)
			m, perr := msg.ParseV3(dg)
			if perr == nil && m.Header.SecModel == msg.SecurityModelUSM &&
				len(m.USM.EngineID) == 0 && m.USM.UserName == "" &&
				m.Header.MsgFlags&msg.MsgFlagReportable != 0 {
				// Discovery probe: answer with OUR engine (receiver is
				// authoritative for informs).
				probeCount <- 1
				report := msg.BuildPDU(msg.PDUReport, 1, 0, 0,
					msg.AppendTLV(nil, 0x30, msg.AppendTLV(msg.AppendTLV(nil, 0x06, mustOID(t, "1.3.6.1.6.3.15.1.1.4.0")), 0x41, []byte{0, 0, 0, 0})))
				scoped := msg.BuildScoped(sinkEngine, nil, report)
				out, berr := msg.BuildV3(msg.V3Header{
					MsgID:      m.Header.MsgID,
					MsgMaxSize: msg.DefaultMsgMaxSize,
					MsgFlags:   msg.MsgFlagReportable,
					SecModel:   msg.SecurityModelUSM,
				}, msg.USMParams{
					EngineID: sinkEngine,
					Boots:    sinkBoots,
					Time:     sinkTime,
				}, scoped, nil)
				if berr == nil {
					_, _ = conn.WriteTo(out, from)
				}
				continue
			}
			select {
			case inbox <- dg:
			default:
			}
		}
	}()
	return conn.LocalAddr().String(),
		func(t *testing.T) []byte {
			t.Helper()
			select {
			case dg := <-inbox:
				return dg
			case <-time.After(5 * time.Second):
				t.Fatal("the gateway never delivered a notification to the sink")
				return nil
			}
		},
		func() int {
			n := 0
			for {
				select {
				case <-probeCount:
					n++
				default:
					return n
				}
			}
		}
}

func mustOID(t *testing.T, s string) []byte {
	t.Helper()
	b, err := msg.EncodeOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// notifyGateway starts a notification-only gateway (trap listener in, v3
// notifications out to sinkAddr) and returns its trap listener address.
func notifyGateway(t *testing.T, sinkAddr string) (trapAddr string, g *GatewayTranslator) {
	t.Helper()
	return notifyGatewayOn(t, "127.0.0.1", sinkAddr)
}

// notifyGatewayOn is notifyGateway with an explicit trap-listener host.
func notifyGatewayOn(t *testing.T, host, sinkAddr string) (trapAddr string, g *GatewayTranslator) {
	t.Helper()
	store, err := cache.Open("")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := cache.NewEngineClock(store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	trapAddr = freeUDPPortTOn(t, host)
	tr, err := NewGatewayTranslator(config.GatewayRole{
		TrapListenAddr: trapAddr,
		TrapSinkAddr:   sinkAddr,
	}, []Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
	}}, clock, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() { runErr <- tr.Run(done, ready) }()
	select {
	case <-ready:
	case err := <-runErr:
		t.Fatalf("gateway startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("gateway startup timed out")
	}
	t.Cleanup(func() {
		close(done)
		select {
		case <-runErr:
		case <-time.After(5 * time.Second):
			t.Error("gateway did not stop")
		}
	})
	return trapAddr, tr
}

// freeUDPPortTOn binds a free UDP port on an explicit host and releases it.
func freeUDPPortTOn(t *testing.T, host string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

// sendClearInform sends a v2c inform from a device socket at trapAddr.
func sendClearInform(t *testing.T, trapAddr string, pduType uint8) {
	t.Helper()
	sendClearInformOn(t, "127.0.0.1", trapAddr, pduType)
}

// sendClearInformOn is the device side of sendClearInform on an explicit
// family (the device and the trap listener must share it).
func sendClearInformOn(t *testing.T, host, trapAddr string, pduType uint8) {
	t.Helper()
	vbs := msg.AppendTLV(nil, 0x30,
		msg.AppendTLV(msg.AppendTLV(nil, 0x06, mustOID(t, "1.3.6.1.2.1.1.3.0")), 0x43, []byte{0, 0, 0, 0}))
	pdu := msg.BuildPDU(pduType, 4242, 0, 0, vbs)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dst, err := net.ResolveUDPAddr("udp", trapAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo(dg, dst); err != nil {
		t.Fatal(err)
	}
}

// TestGatewayInformTargetsSinkEngine: an inform must be addressed to the
// receiver's engine (discovered first) and signed with keys localized to it.
func TestGatewayInformTargetsSinkEngine(t *testing.T) {
	sinkAddr, next, probeCount := fakeAuthoritativeSink(t)
	trapAddr, g := notifyGateway(t, sinkAddr)

	sendClearInform(t, trapAddr, msg.PDUInformRequest)
	dg := next(t)

	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("wrapped inform undecodable: %v", err)
	}
	if !bytes.Equal(m.USM.EngineID, sinkEngine) {
		t.Fatalf("inform msgAuthoritativeEngineID = %x, want the SINK's engine %x (receiver-authoritative, RFC 3414 §2.2)",
			m.USM.EngineID, sinkEngine)
	}
	if m.USM.Boots != sinkBoots || m.USM.Time != sinkTime {
		t.Fatalf("inform boots/time = %d/%d, want the discovered %d/%d",
			m.USM.Boots, m.USM.Time, sinkBoots, sinkTime)
	}
	if m.USM.UserName != "proxy" {
		t.Fatalf("inform user = %q", m.USM.UserName)
	}
	if probeCount() == 0 {
		t.Fatal("the gateway never probed the sink for its engine")
	}

	// The keys must be localized to the SINK's engine: verifying with
	// keys built for our own engine fails, which is exactly what a strict
	// receiver would do.
	keys, err := g.keys.profilesFor(sinkEngine)
	if err != nil {
		t.Fatalf("profiles for sink engine: %v", err)
	}
	_, pdu, err := unwrapV3(keys, m, dg)
	if err != nil {
		t.Fatalf("inform does not verify with keys localized to the sink engine: %v", err)
	}
	if len(pdu) == 0 || pdu[0] != msg.PDUInformRequest {
		t.Fatalf("wrapped PDU type = %x, want InformRequest", pdu[0])
	}
}

// TestGatewayTrapStaysSenderAuthoritative: the trap path must NOT change.
// A trap names OUR engine and is never preceded by a discovery probe — a
// receiver that cannot learn our engine would silently drop it.
func TestGatewayTrapStaysSenderAuthoritative(t *testing.T) {
	sinkAddr, next, probeCount := fakeAuthoritativeSink(t)
	trapAddr, g := notifyGateway(t, sinkAddr)

	sendClearInform(t, trapAddr, msg.PDUSNMPv2Trap)
	dg := next(t)

	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("wrapped trap undecodable: %v", err)
	}
	if !bytes.Equal(m.USM.EngineID, g.clock.EngineID()) {
		t.Fatalf("trap msgAuthoritativeEngineID = %x, want our own engine %x (sender-authoritative)",
			m.USM.EngineID, g.clock.EngineID())
	}
	if m.Header.MsgFlags&msg.MsgFlagReportable != 0 {
		t.Fatal("a trap must not be reportable (unconfirmed class, RFC 3412 §6.4)")
	}
	if n := probeCount(); n != 0 {
		t.Fatalf("the gateway probed the sink %d times for a TRAP; traps need no discovery", n)
	}
	keys, err := g.keys.profilesFor(g.clock.EngineID())
	if err != nil {
		t.Fatal(err)
	}
	_, pdu, err := unwrapV3(keys, m, dg)
	if err != nil {
		t.Fatalf("trap does not verify with keys localized to our engine: %v", err)
	}
	if len(pdu) == 0 || pdu[0] != msg.PDUSNMPv2Trap {
		t.Fatalf("wrapped PDU type = %x, want SNMPv2-Trap", pdu[0])
	}
}

// restartedBoots/restartedTime are the state a fake receiver announces in the
// middle of an inform round trip, simulating a restart.
const (
	restartedBoots = uint32(8)
	restartedTime  = uint32(900)
)

// fakeRestartingSink answers discovery with sinkBoots/sinkTime, then answers
// the inform with a signed Report announcing RESTARTED engine state (the
// usmStatsNotInTimeWindows answer a strict receiver sends when the sender's
// boots/time are stale). It records the inbound informs and the number of
// discovery probes it served.
func fakeRestartingSink(t *testing.T) (addr string, informs <-chan []byte, probes func() int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	profs, err := NewProfiles([]Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
	}}, sinkEngine)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := profs.Lookup("proxy")
	if !ok {
		t.Fatal("fake sink profile missing")
	}
	authParams := make([]byte, c.Profile().AuthProtocol.MacLength())

	notInTimeWindow := msg.AppendTLV(nil, 0x30,
		msg.AppendTLV(msg.AppendTLV(nil, 0x06, mustOID(t, "1.3.6.1.6.3.15.1.1.2.0")), 0x41, []byte{0, 0, 0, 0}))

	// report builds a Report for the sink's engine. signed=false is the
	// discovery answer (NoAuthNoPriv, RFC 3414 §4); signed=true is the
	// answer to one of our informs, authenticated with the user's keys
	// localized to the sink's engine — exactly like a real receiver.
	report := func(t *testing.T, msgID int32, boots, etime uint32, signed bool) []byte {
		t.Helper()
		hdr := msg.V3Header{
			MsgID:      msgID,
			MsgMaxSize: msg.DefaultMsgMaxSize,
			MsgFlags:   msg.MsgFlagReportable,
			SecModel:   msg.SecurityModelUSM,
		}
		usmParams := msg.USMParams{EngineID: sinkEngine, Boots: boots, Time: etime}
		if signed {
			hdr.MsgFlags = msg.MsgFlagAuth
			usmParams.UserName = "proxy"
			usmParams.AuthParams = append([]byte{}, authParams...)
		}
		pdu := msg.BuildPDU(msg.PDUReport, 1, 0, 0, notInTimeWindow)
		scoped := msg.BuildScoped(sinkEngine, nil, pdu)
		out, berr := msg.BuildV3(hdr, usmParams, scoped, nil)
		if berr != nil {
			t.Errorf("fake sink: build report: %v", berr)
			return nil
		}
		if signed {
			if serr := SignV3(out, c.Profile().AuthProtocol, c.AuthKey()); serr != nil {
				t.Errorf("fake sink: sign report: %v", serr)
				return nil
			}
		}
		return out
	}

	var probeCount atomic.Int32
	inbox := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			m, perr := msg.ParseV3(append([]byte{}, buf[:n]...))
			if perr != nil {
				continue
			}
			if len(m.USM.EngineID) == 0 && m.USM.UserName == "" {
				probeCount.Add(1)
				if out := report(t, m.Header.MsgID, sinkBoots, sinkTime, false); out != nil {
					_, _ = conn.WriteTo(out, from)
				}
				continue
			}
			// Our inform: refuse it with the RESTARTED state, as a strict
			// receiver does for a stale boots/time claim.
			if out := report(t, m.Header.MsgID, restartedBoots, restartedTime, true); out != nil {
				_, _ = conn.WriteTo(out, from)
			}
			select {
			case inbox <- append([]byte{}, buf[:n]...):
			default:
			}
		}
	}()
	return conn.LocalAddr().String(), inbox,
		func() int { return int(probeCount.Load()) }
}

// TestGatewayFollowsSinkRestartFromResponse: a verified answer from the sink
// is authoritative wire state. When the receiver rejects an inform because
// it restarted, the Report carries its new boots/time; the gateway must adopt
// it and wrap the NEXT inform against that state — without waiting out the
// 60s discovery TTL, and without a second discovery probe. Without adoption
// every inform stays stale for a minute after a receiver restart, and a
// receiver that answers without a GetResponse (usmStatsNotInTimeWindows)
// gives the sender no other signal.
func TestGatewayFollowsSinkRestartFromResponse(t *testing.T) {
	sinkAddr, informs, probes := fakeRestartingSink(t)
	trapAddr, g := notifyGateway(t, sinkAddr)

	sendClearInform(t, trapAddr, msg.PDUInformRequest)
	select {
	case <-informs:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never sent the first inform to the sink")
	}

	// adoption happens in the trap read loop right after the answer is
	// verified; poll the cached state instead of sleeping.
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.sinkEngMu.Lock()
		boots := uint32(0)
		if g.sinkEng != nil {
			boots = g.sinkEng.boots
		}
		g.sinkEngMu.Unlock()
		if boots == restartedBoots {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not adopt the sink's restarted boots (still %d, want %d)", boots, restartedBoots)
		}
		time.Sleep(10 * time.Millisecond)
	}

	sendClearInform(t, trapAddr, msg.PDUInformRequest)
	var wrapped []byte
	select {
	case wrapped = <-informs:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never sent the second inform")
	}
	m, err := msg.ParseV3(wrapped)
	if err != nil {
		t.Fatalf("second inform undecodable: %v", err)
	}
	if m.USM.Boots != restartedBoots || m.USM.Time != restartedTime {
		t.Fatalf("second inform boots/time = %d/%d, want the adopted %d/%d from the sink's Report",
			m.USM.Boots, m.USM.Time, restartedBoots, restartedTime)
	}
	if n := probes(); n != 1 {
		t.Fatalf("sink probed %d times, want exactly 1 (adoption must replace re-discovery)", n)
	}
}
