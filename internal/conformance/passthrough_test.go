// passthrough_test.go — the two-proxy chain in `passthrough` mode, driven by
// the vendor peers.
//
// Every other chain scenario runs `usm-translate`, where the proxies parse and
// re-wrap each message. `passthrough` is the opposite promise: the datagram is
// forwarded unchanged, so whatever the vendor put on the wire is what the far
// side receives. That promise is only worth something if a real stack checks
// it, and until this file existed **no vendor had ever sent a notification
// through a passthrough tunnel**: the mode's notification legs were dead (the
// agent side had no NOTIF subscriber at all, and informs were never
// confirmed), which no amount of self-consistency testing could show.
//
// Four shapes, because the two directions have separate code paths:
//
//	manager-side device → tunnel → agent-side sink   (trap + inform)
//	agent-side device   → tunnel → manager-side sink (trap + inform)
//
// An inform additionally has to be confirmed to the sending device: the vendor
// adapter reports `ok` only when the confirmation arrived, on the socket it
// sent from, with its own request-id.
package conformance

import (
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// passthroughChain is the two-proxy deployment with `security.mode:
// passthrough`, wired with a notification ingress on each side and a sink
// behind each ingress.
type passthroughChain struct {
	// Front is the manager's clear request leg.
	Front string
	// MgrTrap / AgentTrap are the two notification ingresses: a notification
	// accepted on one is delivered to the sink on the other side.
	MgrTrap   string
	AgentTrap string
	// MgrSideSink is the real manager's trap receiver: it sits behind the
	// MANAGER-side proxy, so it gets the notifications accepted on the AGENT
	// side. AgentSideSink is the mirror: it sits behind the AGENT-side proxy
	// and gets the notifications accepted on the MANAGER side.
	MgrSideSink   *testkit.TrapSink
	AgentSideSink *testkit.TrapSink
	Device        *testkit.Agent
}

func startPassthroughChain(t *testing.T, p Peer) *passthroughChain {
	t.Helper()
	dev := newDevice(t, testkit.AgentOptions{})
	// Both sinks answer informs: the confirmation then has to travel the
	// whole chain, which is the property that was broken.
	agentSideSink := testkit.NewAnsweringTrapSink(t)
	mgrSideSink := testkit.NewAnsweringTrapSink(t)

	bindFront, front := peerFront(t, p)
	bindMgrTrap, mgrTrap := peerFront(t, p)
	bindAgentTrap, agentTrap := peerFront(t, p)
	tunnelAddr := testkit.FreeUDPPort(t, "")
	psk := randomPSK(t)

	agentProc := startProxy(t, "agent",
		"agent", "--security", "passthrough",
		"--tunnel-addr", tunnelAddr, "--psk", psk,
		"--agent", dev.Addr(), "--community", community,
		"--trap-listen", bindAgentTrap,
		"--trap-sink", agentSideSink.Addr(),
		"--log-level", "debug",
	)
	// Only the TUNNEL listener is process-scoped on the agent side; its
	// device-notification ingress is created per accepted tunnel session
	// (passthrough forwards raw datagrams, so the reader lives with the
	// session). So wait for it AFTER the manager has dialed, not before —
	// before the first session exists there is nothing to bind.
	agentProc.waitFront(t, tunnelAddr)

	mgrProc := startProxy(t, "manager",
		"manager", "--security", "passthrough",
		"--tunnel-addr", tunnelAddr, "--psk", psk,
		"--listen", bindFront, "--community", community,
		"--trap-listen", bindMgrTrap,
		"--trap-sink", mgrSideSink.Addr(),
		"--log-level", "debug",
	)
	mgrProc.waitFront(t, front)
	mgrProc.waitFront(t, mgrTrap)
	agentProc.waitFront(t, agentTrap)
	// A bound port is not a working tunnel: wait for an answer end to end.
	waitV2cReady(t, front)

	return &passthroughChain{
		Front: front, MgrTrap: mgrTrap, AgentTrap: agentTrap,
		MgrSideSink: mgrSideSink, AgentSideSink: agentSideSink,
		Device: dev,
	}
}

// TestPassthroughChainNotifications pins both notification directions through
// an opaque tunnel, for traps and informs.
func TestPassthroughChainNotifications(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startPassthroughChain(t, p)

		// direction names the ingress and the sink the event must reach.
		type direction struct {
			name     string
			ingress  string
			sink     *testkit.TrapSink
			sinkName string
		}
		dirs := []direction{
			{"manager-to-agent", f.MgrTrap, f.AgentSideSink, "agent-side"},
			{"agent-to-manager", f.AgentTrap, f.MgrSideSink, "manager-side"},
		}

		for _, d := range dirs {
			d := d
			t.Run(d.name+"/trap", func(t *testing.T) {
				const trapOID = "1.3.6.1.4.1.99.31.1"
				res := mustRun(t, p, Request{
					Verb: VerbTrap, Version: "2c", Community: community,
					Target:   d.ingress,
					OIDs:     []string{trapOID},
					Varbinds: []string{"1.3.6.1.4.1.99.31.2.0=string:passthrough"},
					Timeout:  2,
				})
				skipUnsupported(t, res)
				requireOK(t, res)

				// Passthrough must not rewrite the notification, so the
				// trap OID arrives exactly as the vendor sent it (no
				// translation, no community rewrite) and the version stays
				// v2c.
				dg := d.sink.WaitForTrapOID(t, trapOID, 10*time.Second)
				info, err := msg.Peek(dg)
				if err != nil {
					t.Fatalf("%s sink received an unparseable notification: %v", d.sinkName, err)
				}
				if info.Version != msg.Version2c {
					t.Fatalf("%s sink received version %d, want v2c (passthrough forwards the datagram unchanged)",
						d.sinkName, info.Version)
				}
				if info.PDUType != msg.PDUSNMPv2Trap {
					t.Fatalf("%s sink received PDU type %#x, want an SNMPv2-Trap", d.sinkName, info.PDUType)
				}
			})

			t.Run(d.name+"/inform", func(t *testing.T) {
				// The confirmation has to survive the whole chain: vendor →
				// proxy → tunnel → proxy → sink, and back. The adapter
				// reports ok only when it matched its own request-id on a
				// connected socket, so a relayed-but-unconfirmed inform
				// fails here — the exact shape of the bug this pins.
				before := d.sink.Count()
				res := mustRun(t, p, Request{
					Verb: VerbInform, Version: "2c", Community: community,
					Target:  d.ingress,
					OIDs:    []string{"1.3.6.1.4.1.99.32.1"},
					Timeout: 3, Retries: 1,
				})
				skipUnsupported(t, res)
				if !res.OK {
					t.Fatalf("inform not confirmed by the vendor (kind=%q); the %s sink received %d notification(s) — "+
						"0 means the proxy never relayed it, >0 means the confirmation did not get back",
						res.ErrorKind, d.sinkName, d.sink.Count()-before)
				}
				// Wait for the sink's own reader: the confirmation reaches the
				// vendor as soon as the proxy wrote to the sink, so the sink's
				// goroutine may not have recorded the datagram yet. Asserting
				// Count() immediately is a race that fails a working relay.
				d.sink.WaitFor(t, before+1, 10*time.Second)
			})
		}

		// The request leg must keep working alongside both notification
		// legs: the tunnel is one session carrying all three frame types.
		t.Run("requests-still-work", func(t *testing.T) {
			res := mustRun(t, p, Request{
				Verb: VerbGet, Version: "2c", Community: community,
				Target: f.Front, OIDs: []string{sysDescr}, Timeout: 3,
			})
			requireOK(t, res)
		})
	})
}

// TestPassthroughChainKeepsTheWireFormat goes one step further than the
// notification scenarios: the sink must receive the notification the device
// sent, not a re-encoding of it. A proxy that parsed and rebuilt a trap could
// still deliver something "correct" while rewriting the community (as the
// translating modes do on purpose: the far side imposes
// `trap_sink_community`) or dropping a varbind the vendor added.
//
// The check is deliberately vendor-independent: a distinctive community plus a
// varbind with an unusual value survives every stack's encoder, while a v1
// trap's enterprise/generic/specific split is adapter-defined (net-snmp turns
// the trailing arc into specific-trap, gosnmp splits explicitly, pysnmp builds
// its own v1 shape), so asserting on it would test the adapter, not the proxy.
// The "v1 stays v1" property is pinned in-Go by
// internal/passthrough/e2e_reverse_notif_test.go.
func TestPassthroughChainKeepsTheWireFormat(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startPassthroughChain(t, p)

		const (
			deviceCommunity = "device-community"
			trapOID         = "1.3.6.1.4.1.99.33.1"
			valueOID        = "1.3.6.1.4.1.99.33.2.0"
			value           = "passthrough-not-rewritten"
		)
		res := mustRun(t, p, Request{
			Verb: VerbTrap, Version: "2c", Community: deviceCommunity,
			Target:   f.MgrTrap,
			OIDs:     []string{trapOID},
			Varbinds: []string{valueOID + "=string:" + value},
			Timeout:  2,
		})
		skipUnsupported(t, res)
		requireOK(t, res)

		dg := f.AgentSideSink.WaitForTrapOID(t, trapOID, 10*time.Second)
		info, err := msg.Peek(dg)
		if err != nil {
			t.Fatalf("agent-side sink received an unparseable notification: %v", err)
		}
		if info.Version != msg.Version2c {
			t.Fatalf("notification version = %d, want v2c: passthrough must not translate", info.Version)
		}
		ver, comm, pduTLV, err := msg.SplitV1V2c(dg)
		if err != nil {
			t.Fatalf("notification is not a v1/v2c datagram: %v", err)
		}
		if ver != msg.Version2c || string(comm) != deviceCommunity {
			t.Fatalf("notification version/community = %d/%q, want v2c/%q (the device's own, not the proxy's)",
				ver, comm, deviceCommunity)
		}
		_, fields, err := msg.ParsePDU(pduTLV)
		if err != nil {
			t.Fatalf("notification PDU: %v", err)
		}
		vbs, err := msg.ParseVarbinds(fields.Varbinds)
		if err != nil {
			t.Fatalf("notification varbinds: %v", err)
		}
		for _, vb := range vbs {
			if vb.OID == valueOID {
				if string(vb.Value) != value {
					t.Fatalf("varbind %s = %q, want %q: passthrough must not re-encode varbind values",
						valueOID, vb.Value, value)
				}
				return
			}
		}
		t.Fatalf("notification lost varbind %s (got %d varbind(s): %+v)", valueOID, len(vbs), vbs)
	})
}
