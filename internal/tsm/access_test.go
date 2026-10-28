// access_test.go (package tsm_test): the TSM gateway's front-leg access
// policy, pinned on the wire. A refused SET must be answered with
// notWritable (so the manager learns immediately, and net-snmp/gosnmp
// style clients see a normal error-status) and must never reach the legacy
// device.
package tsm_test

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/tsm"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// buildTSMSet builds a TSM v3 SET request touching sysName.0.
func buildTSMSet(t *testing.T, msgID, reqID int32) []byte {
	t.Helper()
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	vb := msg.AppendTLV(nil, 0x06, oid)
	vb = msg.AppendTLV(vb, 0x04, []byte("nope"))
	vbs := msg.AppendTLV(nil, 0x30, vb)
	pdu := msg.BuildPDU(msg.PDUSetRequest, reqID, 0, 0, vbs)
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      msgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTSMGatewayReadOnlyRefusesWrites: with access.read_only the TSM gateway
// answers a SET with notWritable and forwards nothing to the agent.
func TestTSMGatewayReadOnlyRefusesWrites(t *testing.T) {
	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)

	// a fake agent that records every datagram it receives
	agentConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.Close()
	got := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, rerr := agentConn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			select {
			case got <- append([]byte(nil), buf[:n]...):
			default:
			}
		}
	}()

	front := freeUDPPort(t)
	cfg := config.GatewayRole{
		ListenAddr:     front,
		AgentAddr:      agentConn.LocalAddr().String(),
		AgentCommunity: "realcomm",
	}
	sec := config.Security{Mode: "tsm-gateway", TSMIdentities: []string{"snmp-shield-manager"}}
	lcfg := tunnel.ListenerConfig{Mode: "dtls", CAFile: ca, CertFile: serverCrt, KeyFile: serverKey}
	gw, err := tsm.NewTSMGateway(cfg, sec, lcfg, 0, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := access.New(nil, 0, access.NewReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	gw.SetAccess(access.NewHolder(pol))

	done := make(chan struct{})
	defer close(done)
	go func() { _ = gw.Run(done) }()
	waitFrontBound(t, front)

	conn := dialFront(t, front, ca, clientCrt, clientKey)
	defer conn.Close()

	if _, werr := conn.Write(buildTSMSet(t, 2001, 555)); werr != nil {
		t.Fatalf("write TSM SET: %v", werr)
	}

	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, rerr := conn.Read(buf)
	if rerr != nil {
		t.Fatalf("no TSM answer for the refused SET: %v", rerr)
	}
	m, perr := msg.ParseV3(buf[:n])
	if perr != nil {
		t.Fatalf("bad response datagram: %v", perr)
	}
	if m.Header.SecModel != msg.SecurityModelTSM {
		t.Fatalf("response SecModel = %d, want TSM", m.Header.SecModel)
	}
	if m.Header.MsgID != 2001 {
		t.Errorf("response msgID = %d, want the request's 2001", m.Header.MsgID)
	}
	if m.Header.MsgFlags&msg.MsgFlagReportable != 0 {
		t.Errorf("response flags = %#x: a locally generated refusal is still a Response (unconfirmed class)", m.Header.MsgFlags)
	}
	if len(m.PDU) == 0 || m.PDU[0] != msg.PDUGetResponse {
		t.Fatalf("response PDU type = %v, want GetResponse", m.PDU)
	}
	_, fields, perr := msg.ParsePDU(m.PDU)
	if perr != nil {
		t.Fatalf("bad response PDU: %v", perr)
	}
	if fields.ErrStatus != msg.ErrStatusNotWritable {
		t.Errorf("errStatus = %d, want notWritable (%d)", fields.ErrStatus, msg.ErrStatusNotWritable)
	}
	if fields.ReqID != 555 {
		t.Errorf("response req-id = %d, want the request's 555", fields.ReqID)
	}

	select {
	case dg := <-got:
		t.Fatalf("refused SET reached the legacy agent: %x", dg)
	case <-time.After(500 * time.Millisecond):
	}
}
