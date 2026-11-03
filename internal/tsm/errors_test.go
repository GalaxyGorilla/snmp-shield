// Direct tests for TSM's unexported validation and pending-state helpers.
//
// The e2e tests cover the happy path against real DTLS peers; these pin the
// rejection paths that a hostile or buggy peer reaches: a certificate with
// no usable identity, a non-TSM or encrypted message where TSM is required,
// and pending entries that must not survive an unknown correlation ID.
package tsm

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

func TestSecurityNameFromCerts(t *testing.T) {
	cases := []struct {
		name  string
		certs []*x509.Certificate
		want  string
		ok    bool
	}{
		{"no certificates", nil, "", false},
		{"common name", []*x509.Certificate{{Subject: pkix.Name{CommonName: "plant-01"}}}, "plant-01", true},
		{"dns san fallback", []*x509.Certificate{{DNSNames: []string{"hmi.example"}}}, "hmi.example", true},
		{"email san fallback", []*x509.Certificate{{EmailAddresses: []string{"ops@example"}}}, "ops@example", true},
		{"no identity", []*x509.Certificate{{}}, "", false},
		{"first certificate wins", []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "leaf"}},
			{Subject: pkix.Name{CommonName: "issuer"}},
		}, "leaf", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := securityNameFromCerts(c.certs)
			if c.ok {
				if err != nil {
					t.Fatalf("securityNameFromCerts: %v", err)
				}
				if got != c.want {
					t.Fatalf("securityNameFromCerts = %q, want %q", got, c.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("securityNameFromCerts = %q, want an error", got)
			}
		})
	}
}

func TestUnwrapTSMRejectsNonTSMAndEncrypted(t *testing.T) {
	if _, err := unwrapTSM(&msg.V3Message{
		Header: msg.V3Header{SecModel: msg.SecurityModelUSM},
	}); err == nil {
		t.Fatal("a USM message was accepted as TSM")
	}
	if _, err := unwrapTSM(&msg.V3Message{
		Header: msg.V3Header{SecModel: msg.SecurityModelTSM},
		PDU:    []byte{0x04, 0x00}, // OCTET STRING: encrypted scopedPDU
	}); err == nil {
		t.Fatal("an encrypted scopedPDU was accepted by TSM (TSM has no privacy)")
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 7, 0, 0, nil)
	got, err := unwrapTSM(&msg.V3Message{
		Header: msg.V3Header{SecModel: msg.SecurityModelTSM},
		PDU:    pdu,
	})
	if err != nil {
		t.Fatalf("plain TSM scopedPDU rejected: %v", err)
	}
	if string(got) != string(pdu) {
		t.Fatal("unwrapTSM did not return the inner PDU verbatim")
	}
}

func TestParseDERCertsRejectsGarbage(t *testing.T) {
	if got := parseDERCerts([][]byte{{0x01, 0x02, 0x03}}); got != nil {
		t.Fatalf("parseDERCerts(garbage) = %v, want nil", got)
	}
	if got := parseDERCerts(nil); len(got) != 0 {
		t.Fatalf("parseDERCerts(nil) = %v, want empty", got)
	}
}

func TestPeerCertsOfPlainConnIsNil(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := peerCertsOf(a); got != nil {
		t.Fatalf("peerCertsOf(plain conn) = %v, want nil", got)
	}
}

func TestPendingTablesDropUnknownAndKnownEntries(t *testing.T) {
	mgr, err := NewManagerTranslator(config.ManagerRole{}, config.Security{}, nil, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetAccess(nil)
	mgr.pendMu.Lock()
	mgr.pend[1] = &managerPending{}
	mgr.pendMu.Unlock()
	mgr.dropPending(1)
	mgr.dropPending(99) // idempotent for an unknown key
	mgr.pendMu.Lock()
	if len(mgr.pend) != 0 {
		t.Fatalf("manager pending table not empty: %d", len(mgr.pend))
	}
	mgr.pendMu.Unlock()

	agt, err := NewAgentTranslator(config.AgentRole{}, config.Security{}, nil, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	agt.SetAccess(nil)
	agt.pendMu.Lock()
	agt.pend[2] = &agentPending{}
	agt.pendMu.Unlock()
	agt.dropPending(2)
	agt.dropPending(99)
	agt.pendMu.Lock()
	if len(agt.pend) != 0 {
		t.Fatalf("agent pending table not empty: %d", len(agt.pend))
	}
	agt.pendMu.Unlock()

	gw, err := NewTSMGateway(config.GatewayRole{}, config.Security{}, tunnel.ListenerConfig{}, 0, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gw.SetAccess(nil)
	gw.SetSessionLimiter(nil)
	gw.pendMu.Lock()
	gw.pend[3] = &tsmGwPending{}
	gw.pendMu.Unlock()
	gw.dropPending(3)
	gw.dropPending(99)
	gw.pendMu.Lock()
	if len(gw.pend) != 0 {
		t.Fatalf("gateway pending table not empty: %d", len(gw.pend))
	}
	gw.pendMu.Unlock()
}

func TestWaitForInformUnknownIsAlreadyReady(t *testing.T) {
	gw, err := NewTSMGateway(config.GatewayRole{}, config.Security{}, tunnel.ListenerConfig{}, 0, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := gw.waitForInform(1234)
	select {
	case <-ch:
	default:
		t.Fatal("waitForInform for an unknown request blocked; a missing inform must not hang the caller")
	}
}

func TestManagerIgnoresUnknownTunnelResponses(t *testing.T) {
	mgr, err := NewManagerTranslator(config.ManagerRole{}, config.Security{}, nil, zap.NewNop(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// A well-formed TSM response whose correlation ID matches no pending
	// request must be dropped, not panic or deliver to a stale client.
	payload, err := wrapTSM(1, 1, msg.PDUGetResponse, nil, nil, 0, "")
	if err != nil {
		t.Fatalf("wrapTSM: %v", err)
	}
	mgr.handleTunnelResponse(&tunnel.Frame{CorrID: 99, Payload: payload})

	// Garbage, a non-TSM message and a non-response PDU all take an early
	// return. None may touch the pending table.
	mgr.handleTunnelResponse(&tunnel.Frame{CorrID: 99, Payload: []byte{0x30, 0x00}})
	usmPayload, err := msg.BuildV3(msg.V3Header{
		MsgID: 1, MsgMaxSize: msg.DefaultMsgMaxSize, SecModel: msg.SecurityModelUSM,
	}, msg.USMParams{}, msg.BuildScoped(nil, nil, msg.BuildPDU(msg.PDUGetResponse, 1, 0, 0, nil)), nil)
	if err != nil {
		t.Fatalf("build USM payload: %v", err)
	}
	mgr.handleTunnelResponse(&tunnel.Frame{CorrID: 99, Payload: usmPayload})
	mgr.handleTunnelInformResp(&tunnel.Frame{CorrID: 99, Payload: payload})

	mgr.pendMu.Lock()
	defer mgr.pendMu.Unlock()
	if len(mgr.pend) != 0 || len(mgr.inform) != 0 {
		t.Fatalf("rejected messages changed pending state: pend=%d inform=%d", len(mgr.pend), len(mgr.inform))
	}
}
