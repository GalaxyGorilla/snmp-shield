// IPv6 notification-authority pin: the inform path has its own sockets
// (sink discovery is a fresh ephemeral socket, and the notification is sent
// from the trap listener), so the request-path IPv6 test says nothing about
// them. This repeats the conformant-inform assertion — addressed to the
// RECEIVER's discovered engine — on ::1.
package usm

import (
	"bytes"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

func TestGatewayInformIPv6TargetsSinkEngine(t *testing.T) {
	sinkAddr, next, probeCount := fakeAuthoritativeSinkOn(t, "[::1]:0")
	trapAddr, g := notifyGatewayOn(t, "::1", sinkAddr)

	sendClearInformOn(t, "::1", trapAddr, msg.PDUInformRequest)
	dg := next(t)

	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("wrapped inform undecodable: %v", err)
	}
	if !bytes.Equal(m.USM.EngineID, sinkEngine) {
		t.Fatalf("inform engineID = %x, want the sink's %x: discovery over IPv6 failed and the sender-authoritative fallback was used",
			m.USM.EngineID, sinkEngine)
	}
	if m.USM.Boots != sinkBoots || m.USM.Time != sinkTime {
		t.Fatalf("inform boots/time = %d/%d, want %d/%d", m.USM.Boots, m.USM.Time, sinkBoots, sinkTime)
	}
	if probeCount() == 0 {
		t.Fatal("the gateway never probed the IPv6 sink for its engine")
	}

	keys, err := g.keys.profilesFor(sinkEngine)
	if err != nil {
		t.Fatalf("profiles for sink engine: %v", err)
	}
	if _, pdu, err := unwrapV3(keys, m, dg); err != nil {
		t.Fatalf("inform does not verify with sink-localized keys: %v", err)
	} else if len(pdu) == 0 || pdu[0] != msg.PDUInformRequest {
		t.Fatalf("wrapped PDU type = %x, want InformRequest", pdu[0])
	}
}
