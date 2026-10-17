// agent_test.go: unit tests for the SNMP health MIB agent — GET, GETNEXT
// (walk), unknown OID, wrong community and trap emission, all over a real
// loopback UDP socket with hand-built v2c datagrams.
package snmpmetrics

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// testAgent builds an agent with two counters and starts its listener on
// an ephemeral port. Returns the agent and its listen address.
func testAgent(t *testing.T, community string) (*Agent, string) {
	t.Helper()
	c1 := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_c1"})
	c1.Add(42)
	c2 := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_c2"})
	c2.Add(7)
	a := New(Config{
		Community:  community,
		Version:    "9.9.9",
		Role:       "manager",
		SecMode:    "usm-translate",
		TunnelMode: "dtls",
		Endpoints:  "10.0.0.1:19611,10.0.0.2:19611",
	}, []prometheus.Counter{c1, c2}, nil, zap.NewNop())
	addr := freeUDPPort(t)
	stop := make(chan struct{})
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- a.Serve(addr, stop, ready)
		close(runErr)
	}()
	select {
	case <-ready:
	case err, ok := <-runErr:
		if !ok {
			t.Fatal("snmp metrics agent exited during startup without an error")
		}
		t.Fatalf("snmp metrics agent exited during startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for snmp metrics agent startup")
	}
	t.Cleanup(func() {
		close(stop)
		select {
		case err, ok := <-runErr:
			if ok && err != nil {
				t.Errorf("snmp metrics agent exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("snmp metrics agent did not stop within 5 seconds")
		}
	})
	return a, addr
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// buildGet builds a v2c GET (or GETNEXT) datagram for oids. The request
// id is returned alongside the datagram so silence-expecting tests can
// tell a REAL response (matching req-id) from foreign loopback noise
// (under a fully loaded suite, parallel packages share the loopback
// namespace and a recycled ephemeral port can receive a stray datagram
// from another test's server — that noise must not fail a
// wrong-community-silence assertion).
func buildGet(t *testing.T, community string, pduType uint8, oids ...string) ([]byte, int32) {
	t.Helper()
	var vb []byte
	for _, o := range oids {
		oidBytes, err := msg.EncodeOID(o)
		if err != nil {
			t.Fatal(err)
		}
		vb = msg.AppendTLV(vb, 0x30, msg.AppendOIDTLV(nil, oidBytes))
	}
	pdu := msg.BuildPDU(pduType, 1234, 0, 0, vb)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte(community), pdu)
	if err != nil {
		t.Fatal(err)
	}
	return dg, 1234
}

// buildGetDg is buildGet for tests that only need the datagram (the
// response req-id is asserted via parseResponse anyway).
func buildGetDg(t *testing.T, community string, pduType uint8, oids ...string) []byte {
	t.Helper()
	dg, _ := buildGet(t, community, pduType, oids...)
	return dg
}

// exchange sends dg to the agent and returns the response datagram
// (nil on timeout).
func exchange(t *testing.T, addr string, dg []byte) []byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	if _, err := pc.WriteTo(dg, mustAddr(t, addr)); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func mustAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// parseResponse decodes a v2c GetResponse into reqID + varbind
// {oid: valueTLV-content} pairs.
func parseResponse(t *testing.T, dg []byte) (int32, map[string][]byte) {
	t.Helper()
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		t.Fatalf("split response: %v", err)
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatalf("parse response PDU: %v", err)
	}
	if pduType != msg.PDUGetResponse {
		t.Fatalf("expected GetResponse, got 0x%02x", pduType)
	}
	out := make(map[string][]byte)
	for rest := fields.Varbinds; len(rest) > 0; {
		tag, content, r, err := msg.NextTLV(rest)
		if err != nil || tag != 0x30 {
			t.Fatalf("bad varbind list")
		}
		rest = r
		oidTag, oidContent, valueTLV, err := msg.NextTLV(content)
		if err != nil || oidTag != 0x06 {
			t.Fatalf("bad varbind")
		}
		oid, err := msg.DecodeOID(oidContent)
		if err != nil {
			t.Fatalf("decode OID: %v", err)
		}
		out[oid] = valueTLV
	}
	return fields.ReqID, out
}

func TestSNMPGetScalars(t *testing.T) {
	_, addr := testAgent(t, "metcomm")
	base := "1.3.6.1.4.1.58427.1"
	dg, _ := buildGet(t, "metcomm", msg.PDUGetRequest,
		base+".1", base+".2", base+".3", base+".7", base+".10")
	resp := exchange(t, addr, dg)
	if resp == nil {
		t.Fatal("no response to GET")
	}
	reqID, vbs := parseResponse(t, resp)
	if reqID != 1234 {
		t.Fatalf("reqID echo: got %d", reqID)
	}
	check := func(oid, want string) {
		t.Helper()
		got, ok := vbs[base+oid]
		if !ok {
			t.Fatalf("missing varbind %s", oid)
		}
		if string(got[2:]) != want { // OCTET STRING TLV: tag+len+content
			t.Fatalf("%s: got %q, want %q", oid, string(got[2:]), want)
		}
	}
	check(".1", "snmp-shield")
	check(".2", "9.9.9")
	check(".3", "manager")
}

func TestSNMPGetCountersAndLatency(t *testing.T) {
	_, addr := testAgent(t, "metcomm")
	base := "1.3.6.1.4.1.58427.1"
	resp := exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetRequest, base+".20.1", base+".20.2"))
	if resp == nil {
		t.Fatal("no response to counter GET")
	}
	_, vbs := parseResponse(t, resp)
	if got := vbs[base+".20.1"]; got == nil {
		t.Fatal("missing counter .20.1")
	} else if string(got) != string(msg.AppendInteger(nil, 42)) {
		t.Fatalf("counter .20.1: got %v, want 42", got)
	}
	if got := vbs[base+".20.2"]; got == nil {
		t.Fatal("missing counter .20.2")
	} else if string(got) != string(msg.AppendInteger(nil, 7)) {
		t.Fatalf("counter .20.2: got %v, want 7", got)
	}
	// Out-of-range counter row: noSuchName error response.
	resp = exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetRequest, base+".20.9"))
	if resp == nil {
		t.Fatal("no response to out-of-range counter GET")
	}
	_, _, pdu, err := msg.SplitV1V2c(resp)
	if err != nil {
		t.Fatal(err)
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if pduType != msg.PDUGetResponse || fields.ErrStatus != 2 {
		t.Fatalf("expected noSuchName (errStatus 2), got type 0x%02x errStatus %d", pduType, fields.ErrStatus)
	}
}

func TestSNMPGetNextWalk(t *testing.T) {
	_, addr := testAgent(t, "metcomm")
	base := "1.3.6.1.4.1.58427.1"
	// Walk from the base: must land on .1, then proceed through the table.
	cur := base
	seen := 0
	for i := 0; i < 20; i++ {
		resp := exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetNextRequest, cur))
		if resp == nil {
			t.Fatalf("no response to GETNEXT %s", cur)
		}
		_, vbs := parseResponse(t, resp)
		next, ok := firstOID(t, vbs)
		if !ok {
			t.Fatal("empty GETNEXT response")
		}
		if next == cur {
			t.Fatalf("GETNEXT %s returned the same OID", cur)
		}
		cur = next
		seen++
		if cur == base+".20.2" {
			break // walked far enough to prove ordering
		}
	}
	if seen < 5 {
		t.Fatalf("walk too short: %d hops", seen)
	}
	// End of MIB: GETNEXT past the last object returns endOfMibView.
	resp := exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetNextRequest, base+".31"))
	if resp == nil {
		t.Fatal("no response to GETNEXT past end")
	}
	_, vbs := parseResponse(t, resp)
	val, ok := vbs[base+".31"]
	if !ok {
		t.Fatal("missing varbind for endOfMibView response")
	}
	if len(val) != 2 || val[0] != 0x80 {
		t.Fatalf("expected endOfMibView (0x80 0x00), got %v", val)
	}
}

// firstOID extracts the (single) OID from a parsed response varbind map.
func firstOID(t *testing.T, vbs map[string][]byte) (string, bool) {
	t.Helper()
	for k := range vbs {
		return k, true
	}
	return "", false
}

func TestSNMPWrongCommunitySilent(t *testing.T) {
	_, addr := testAgent(t, "metcomm")
	base := "1.3.6.1.4.1.58427.1"
	dg, reqID := buildGet(t, "wrong", msg.PDUGetRequest, base+".1")
	if resp := exchange(t, addr, dg); isOurResponse(t, resp, reqID) {
		t.Fatal("agent answered a wrong-community request")
	}
}

func TestSNMPGarbageSilent(t *testing.T) {
	_, addr := testAgent(t, "metcomm")
	for _, dg := range [][]byte{
		nil,
		{0x30, 0x03},
		{0x30, 0x82, 0xff, 0xff, 0x00},
		[]byte("not-ber-at-all........"),
	} {
		if resp := exchange(t, addr, dg); isOurResponse(t, resp, 0) {
			t.Fatalf("agent answered garbage %q", dg)
		}
	}
}

// isOurResponse reports whether dg is a real GetResponse from THIS agent
// (v2c with the expected request id). Anything else — foreign loopback
// noise from a recycled ephemeral port, stray datagrams from parallel
// packages — is not an answer to the probe and must not fail a
// silence assertion. nil (timeout) is silence.
func isOurResponse(t *testing.T, dg []byte, reqID int32) bool {
	t.Helper()
	if dg == nil {
		return false
	}
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		return false
	}
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil || pduType != msg.PDUGetResponse {
		return false
	}
	return fields.ReqID == reqID
}

func TestTunnelUpScalarsAndTraps(t *testing.T) {
	a, addr := testAgent(t, "metcomm")
	base := "1.3.6.1.4.1.58427.1"

	// Trap sink: a plain UDP listener.
	sinkPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkPC.Close() }()
	sinkAddr := sinkPC.LocalAddr().String()
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := sinkPC.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Mark the tunnel up: scalars change, trap arrives.
	a.SetTunnelUp(true, "10.0.0.1:19611")
	resp := exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetRequest, base+".10", base+".11"))
	if resp == nil {
		t.Fatal("no response after SetTunnelUp")
	}
	_, vbs := parseResponse(t, resp)
	if got := vbs[base+".10"]; got == nil || string(got) != string(msg.AppendInteger(nil, 1)) {
		t.Fatalf("tunnelUp: got %v, want 1", got)
	}
	if got := vbs[base+".11"]; got == nil || string(got[2:]) != "10.0.0.1:19611" {
		t.Fatalf("tunnelEndpoint: got %v", got)
	}

	// Trap emission.
	if err := a.SendTrap(base+".2.1", mustAddr(t, sinkAddr)); err != nil {
		t.Fatalf("SendTrap: %v", err)
	}
	// Trap is fire-and-forget over UDP; success = no error. A full wire
	// validation of the trap lives in the e2e test (proxy role).

	// Tunnel down.
	a.SetTunnelUp(false, "")
	resp = exchange(t, addr, buildGetDg(t, "metcomm", msg.PDUGetRequest, base+".10"))
	if resp == nil {
		t.Fatal("no response after tunnel down")
	}
	_, vbs = parseResponse(t, resp)
	if got := vbs[base+".10"]; got == nil || string(got) != string(msg.AppendInteger(nil, 0)) {
		t.Fatalf("tunnelUp after down: got %v, want 0", got)
	}
}
