package conformance

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// usmGatewayFixture is a real `snmp-shield gateway --security usm-gateway`
// process: standard SNMPv3 in, clear v2c out to a fake legacy device, plus
// the notification ingress leg.
type usmGatewayFixture struct {
	// Front / TrapAddr are what a scenario dials; BindFront / BindTrap are
	// what the proxy listens on. They differ for a container peer, which
	// cannot reach a loopback-bound listener (see peerFront), and the
	// restart test must rebind on the same address as the first start.
	Front     string
	TrapAddr  string
	BindFront string
	BindTrap  string
	Device    *testkit.Agent
	// Sink is a real USM trap receiver: it verifies the digest, decrypts,
	// and confirms informs, so a notification that arrives proves the wrap
	// is interoperable rather than merely present.
	Sink  *testkit.V3Sink
	Store string
	Proc  *proxyProc
}

func startUSMGateway(t *testing.T, p Peer) *usmGatewayFixture {
	t.Helper()
	dev := newDevice(t, testkit.AgentOptions{})
	bindFront, front := peerFront(t, p)
	bindTrap, trapAddr := peerFront(t, p)
	sink := testkit.NewV3Sink(t, testkit.V3SinkOptions{
		User: gatewayUsr, AuthPass: authPass, PrivPass: privPass,
	})
	store := filepath.Join(t.TempDir(), "engine.json")
	proc := startProxy(t, "usm-gateway",
		"gateway", "--security", "usm-gateway",
		"--listen", bindFront, "--agent", dev.Addr(), "--community", community,
		"--trap-listen", bindTrap, "--trap-sink", sink.Addr,
		"--auth-pass", authPass, "--priv-pass", privPass,
		"--engine-store", store,
	)
	proc.waitFront(t, front)
	proc.waitFront(t, trapAddr)
	return &usmGatewayFixture{
		Front: front, TrapAddr: trapAddr, BindFront: bindFront, BindTrap: bindTrap,
		Device: dev, Sink: sink, Store: store, Proc: proc,
	}
}

// v3 builds a request for the gateway's authoritative USM front leg.
func (f *usmGatewayFixture) v3(verb Verb, oids ...string) Request {
	return Request{
		Verb:    verb,
		Version: "3",
		Target:  f.Front,
		User:    gatewayUsr,
		Auth:    authPass,
		Priv:    privPass,
		OIDs:    oids,
		Timeout: 2,
		Retries: 1,
	}
}

// TestUSMGatewayRequests is the core interoperability claim of the project:
// a stock third-party manager, configured only with a user and passphrases,
// can GET, GETNEXT, GETBULK, WALK and SET through the gateway, and the
// legacy device sees ordinary v2c requests.
func TestUSMGatewayRequests(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startUSMGateway(t, p)

		t.Run("get", func(t *testing.T) {
			res := mustRun(t, p, f.v3(VerbGet, sysDescr))
			requireOK(t, res)
			requireVarbind(t, res, sysDescr, "", "testkit fake agent")
		})

		t.Run("multi-varbind-order", func(t *testing.T) {
			// Order matters: RFC 3416 responses carry one answer per
			// request varbind, in request order. A proxy that reorders
			// corrupts every multi-object GET.
			res := mustRun(t, p, f.v3(VerbGet, sysDescr, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"))
			requireOK(t, res)
			if len(res.Varbinds) != 3 {
				t.Fatalf("got %d varbinds, want 3: %v", len(res.Varbinds), res.Varbinds)
			}
			want := []string{sysDescr, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"}
			for i, oid := range want {
				if trimDot(res.Varbinds[i].OID) != oid {
					t.Fatalf("varbind %d = %s, want %s", i, res.Varbinds[i].OID, oid)
				}
			}
		})

		t.Run("getnext", func(t *testing.T) {
			res := mustRun(t, p, f.v3(VerbGetNext, sysDescr))
			requireOK(t, res)
			requireVarbind(t, res, "1.3.6.1.2.1.1.2.0", "", "")
		})

		t.Run("walk", func(t *testing.T) {
			req := f.v3(VerbWalk, "1.3.6.1.2.1.1")
			req.MaxRepetitions = 5
			res := mustRun(t, p, req)
			requireOK(t, res)
			if len(res.Varbinds) < 4 {
				t.Fatalf("walk returned %d varbinds, want the whole system subtree: %v",
					len(res.Varbinds), res.Varbinds)
			}
			if got := trimDot(res.Varbinds[0].OID); got != sysDescr {
				t.Fatalf("walk started at %s, want %s", got, sysDescr)
			}
		})

		t.Run("getbulk", func(t *testing.T) {
			req := f.v3(VerbGetBulk, "1.3.6.1.2.1.1")
			req.MaxRepetitions = 4
			res := mustRun(t, p, req)
			requireOK(t, res)
			if len(res.Varbinds) < 2 {
				t.Fatalf("getbulk returned %d varbinds: %v", len(res.Varbinds), res.Varbinds)
			}
		})

		t.Run("set", func(t *testing.T) {
			before := f.Device.SETs()
			req := f.v3(VerbSet)
			req.Varbinds = []string{"1.3.6.1.4.1.99.1.1.0=int:42"}
			res := mustRun(t, p, req)
			requireOK(t, res)
			if got := f.Device.SETs(); got != before+1 {
				t.Fatalf("device saw %d SET(s), want %d", got, before+1)
			}
		})

		t.Run("missing-object-is-an-exception", func(t *testing.T) {
			// A missing OID is answered, not dropped: SNMPv2 carries
			// noSuchObject/noSuchInstance as a varbind value. Vendors
			// surface it differently (a value, or a varbind error), so
			// accept either but require that the proxy did not hang.
			res := mustRun(t, p, f.v3(VerbGet, "1.3.6.1.4.1.99.9.9.0"))
			if res.OK {
				if len(res.Varbinds) != 1 {
					t.Fatalf("want one exception varbind, got %v", res.Varbinds)
				}
				kind := res.Varbinds[0].Type
				if !strings.Contains(kind, "NoSuch") && !strings.Contains(res.Varbinds[0].Value, "No Such") {
					t.Fatalf("want a noSuch* answer, got %+v", res.Varbinds[0])
				}
				return
			}
			if res.ErrorKind != KindStatus {
				t.Fatalf("want an exception/status, got kind=%q: %s", res.ErrorKind, res.Error)
			}
		})
	})
}

// TestUSMGatewayRejections pins the protection the gateway exists for: the
// front leg is USM only, and a wrong credential must never reach the device.
func TestUSMGatewayRejections(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startUSMGateway(t, p)
		devGETs := f.Device.GETs()

		cases := []struct {
			name string
			req  Request
			// kinds are the admissible failure classifications. Vendors
			// disagree on wording; they must all refuse.
			kinds []string
		}{
			{
				name:  "unknown-user",
				req:   func() Request { r := f.v3(VerbGet, sysDescr); r.User = "ghost"; return r }(),
				kinds: []string{KindAuth, KindTimeout, KindIndication},
			},
			{
				name:  "wrong-auth-passphrase",
				req:   func() Request { r := f.v3(VerbGet, sysDescr); r.Auth = "not-the-pass"; return r }(),
				kinds: []string{KindAuth, KindTimeout, KindDecrypt, KindIndication},
			},
			{
				name:  "wrong-priv-passphrase",
				req:   func() Request { r := f.v3(VerbGet, sysDescr); r.Priv = "not-the-pass"; return r }(),
				kinds: []string{KindDecrypt, KindAuth, KindTimeout, KindIndication},
			},
			{
				// The user is configured at authPriv; requesting less
				// must be refused, not silently downgraded.
				name:  "lower-security-level-than-configured",
				req:   func() Request { r := f.v3(VerbGet, sysDescr); r.Level = "authnopriv"; return r }(),
				kinds: []string{KindSecLevel, KindAuth, KindTimeout, KindIndication, KindStatus},
			},
			{
				name:  "noauthnopriv",
				req:   func() Request { r := f.v3(VerbGet, sysDescr); r.Level = "noauthnopriv"; return r }(),
				kinds: []string{KindSecLevel, KindAuth, KindTimeout, KindIndication, KindStatus},
			},
			{
				// Clear SNMP on a USM front leg is the thing this mode
				// rejects. It must not be answered at all.
				name:  "v2c-on-v3-front-leg",
				req:   Request{Verb: VerbGet, Version: "2c", Community: community, Target: f.Front, OIDs: []string{sysDescr}, Timeout: 1},
				kinds: []string{KindTimeout, KindIndication},
			},
			{
				name:  "v1-on-v3-front-leg",
				req:   Request{Verb: VerbGet, Version: "1", Community: community, Target: f.Front, OIDs: []string{sysDescr}, Timeout: 1},
				kinds: []string{KindTimeout, KindIndication},
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				start := time.Now()
				res := mustRun(t, p, tc.req)
				requireRefused(t, res, tc.kinds...)
				if elapsed := time.Since(start); elapsed > 5*time.Second {
					t.Fatalf("refusal took %s: a credential error should not look like a timeout", elapsed)
				}
				if got := f.Device.GETs(); got != devGETs {
					t.Fatalf("device received %d GET(s) (was %d): a rejected request reached the live device",
						got, devGETs)
				}
			})
		}
	})
}

// TestUSMGatewayEnginePersistence covers the anti-rollback contract across a
// restart: same engineID, higher boots, and a vendor still works afterwards.
// A vendor is the right oracle here because a manager that cached our engine
// keeps using the old boots/time until we announce new ones.
func TestUSMGatewayEnginePersistence(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startUSMGateway(t, p)

		requireOK(t, mustRun(t, p, f.v3(VerbGet, sysDescr)))
		first := readEngineStore(t, f.Store)
		if first.EngineID == "" || first.Boots == 0 {
			t.Fatalf("engine store not written: %+v", first)
		}

		f.Proc.Stop(t)
		f.Proc = startProxy(t, "usm-gateway-restarted",
			"gateway", "--security", "usm-gateway",
			"--listen", f.BindFront, "--agent", f.Device.Addr(), "--community", community,
			"--trap-listen", f.BindTrap, "--trap-sink", f.Sink.Addr,
			"--auth-pass", authPass, "--priv-pass", privPass,
			"--engine-store", f.Store,
		)
		f.Proc.waitFront(t, f.Front)

		second := readEngineStore(t, f.Store)
		if second.EngineID != first.EngineID {
			t.Fatalf("engineID changed across restart: %s -> %s (managers would see a new engine)",
				first.EngineID, second.EngineID)
		}
		if second.Boots <= first.Boots {
			t.Fatalf("engineBoots did not increase across restart: %d -> %d", first.Boots, second.Boots)
		}

		requireOK(t, mustRun(t, p, f.v3(VerbGet, sysDescr)))
	})
}

// TestUSMGatewayNotificationIngress checks the reverse direction: clear
// notification traffic from a legacy device-side agent is wrapped into
// authenticated, encrypted v3 notifications that a strict USM receiver
// verifies and decrypts, and informs are confirmed back to the vendor that
// sent them.
func TestUSMGatewayNotificationIngress(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startUSMGateway(t, p)
		const trapOID = "1.3.6.1.4.1.99.2.1"

		t.Run("v2c-trap-is-wrapped", func(t *testing.T) {
			res := mustRun(t, p, Request{
				Verb: VerbTrap, Version: "2c", Community: community,
				Target: f.TrapAddr, OIDs: []string{trapOID},
				Varbinds: []string{"1.3.6.1.4.1.99.2.2.0=string:hello"},
				Timeout:  2,
			})
			skipUnsupported(t, res)
			requireOK(t, res)
			pkt := f.Sink.WaitForOID(t, trapOID, 10*time.Second)
			if pkt.PDUType != gosnmp.SNMPv2Trap {
				t.Fatalf("sink saw PDU type %v, want SNMPv2-Trap", pkt.PDUType)
			}
			// The payload must travel with the notification: a manager that
			// only receives the trap OID is not receiving the event.
			found := false
			for _, vb := range pkt.Variables {
				if trimDot(vb.Name) != "1.3.6.1.4.1.99.2.2.0" {
					continue
				}
				found = true
				if got, ok := vb.Value.([]byte); !ok || string(got) != "hello" {
					t.Fatalf("payload varbind = %#v, want the string hello", vb.Value)
				}
			}
			if !found {
				t.Fatalf("payload varbind missing from the wrapped notification: %v", pkt.Variables)
			}
		})

		t.Run("v1-trap-is-translated", func(t *testing.T) {
			// RFC 2576: a v1 enterprise-specific trap for enterprise
			// .1.3.6.1.4.1.99, specific 1 becomes .1.3.6.1.4.1.99.0.1 on
			// the v2c side.
			const v1OID = "1.3.6.1.4.1.99.1"
			const translated = "1.3.6.1.4.1.99.0.1"
			res := mustRun(t, p, Request{
				Verb: VerbTrap, Version: "1", Community: community,
				Target: f.TrapAddr, OIDs: []string{v1OID}, Timeout: 2,
			})
			skipUnsupported(t, res)
			requireOK(t, res)
			f.Sink.WaitForOID(t, translated, 10*time.Second)
		})

		t.Run("v2c-inform-is-confirmed", func(t *testing.T) {
			before := f.Sink.Count()
			res := mustRun(t, p, Request{
				Verb: VerbInform, Version: "2c", Community: community,
				Target: f.TrapAddr, OIDs: []string{trapOID}, Timeout: 3, Retries: 1,
			})
			skipUnsupported(t, res)
			// OK means the vendor accepted our confirmation: the inform
			// round trip terminated at the proxy, as it must.
			requireOK(t, res)
			if f.Sink.Count() <= before {
				t.Fatalf("sink saw no forwarded inform (count %d -> %d)", before, f.Sink.Count())
			}
			f.Sink.WaitForOID(t, trapOID, 10*time.Second)
		})
	})
}

// TestUSMGatewayNotifyFilterWire drives the notification filter through a
// vendor. The second OID only *looks* like the denied one: arc boundaries
// are exactly where prefix filters go wrong.
func TestUSMGatewayNotifyFilterWire(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		dev := newDevice(t, testkit.AgentOptions{})
		front := testkit.FreeUDPPort(t, "")
		trapAddr := testkit.FreeUDPPort(t, "")
		sink := testkit.NewV3Sink(t, testkit.V3SinkOptions{
			User: gatewayUsr, AuthPass: authPass, PrivPass: privPass,
		})
		proc := startProxy(t, "usm-gateway-filtered",
			"gateway", "--security", "usm-gateway",
			"--listen", front, "--agent", dev.Addr(), "--community", community,
			"--trap-listen", trapAddr, "--trap-sink", sink.Addr,
			"--auth-pass", authPass, "--priv-pass", privPass,
			"--filter-action", "deny", "--filter-oid", "1.3.6.1.4.1.99.7",
			"--engine-store", filepath.Join(t.TempDir(), "engine.json"),
		)
		proc.waitFront(t, front)
		proc.waitFront(t, trapAddr)

		res := mustRun(t, p, Request{
			Verb: VerbTrap, Version: "2c", Community: community,
			Target: trapAddr, OIDs: []string{"1.3.6.1.4.1.99.7.1"}, Timeout: 2,
		})
		skipUnsupported(t, res)
		requireOK(t, res)

		res = mustRun(t, p, Request{
			Verb: VerbTrap, Version: "2c", Community: community,
			Target: trapAddr, OIDs: []string{"1.3.6.1.4.1.99.70.1"}, Timeout: 2,
		})
		requireOK(t, res)

		// The allowed notification must arrive and the denied one must not.
		// Waiting for the allowed OID first makes the count check meaningful
		// without an arbitrary sleep.
		sink.WaitForOID(t, "1.3.6.1.4.1.99.70.1", 10*time.Second)
		if got := sink.Count(); got != 1 {
			t.Fatalf("sink accepted %d notifications, want exactly 1 (the denied subtree leaked)", got)
		}
	})
}
