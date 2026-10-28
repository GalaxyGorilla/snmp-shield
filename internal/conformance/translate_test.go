package conformance

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// chainFixture is the two-proxy deployment from the README: a legacy v1/v2c
// manager, a manager-side proxy, a PSK-DTLS tunnel, an agent-side proxy and
// a legacy device. Both proxies are real processes; only the vendor client
// and the device are test code.
//
// This is the axis the gateway tests cannot cover: v1/v2c parsing on the
// clear leg, the tunnel envelope, and the agent-side write policy.
type chainFixture struct {
	Front    string
	TrapAddr string
	Device   *testkit.Agent
	// Sink is the real manager's trap receiver behind the agent proxy. It
	// answers informs, so the confirmation has to travel the whole chain.
	Sink *testkit.TrapSink
}

// chainOption customises one side of the chain (used by the policy test).
type chainOption func(agentArgs *[]string)

// withAgentPolicy appends access-policy flags to the DEVICE-facing proxy.
func withAgentPolicy(args ...string) chainOption {
	return func(agentArgs *[]string) { *agentArgs = append(*agentArgs, args...) }
}

func startChain(t *testing.T, device testkit.AgentOptions, opts ...chainOption) *chainFixture {
	t.Helper()
	dev := newDevice(t, device)
	sink := testkit.NewAnsweringTrapSink(t)
	front := testkit.FreeUDPPort(t, "")
	trapAddr := testkit.FreeUDPPort(t, "")
	tunnelAddr := testkit.FreeUDPPort(t, "")
	psk := randomPSK(t)

	// Agent side first: the manager dials it, and the dial must succeed
	// during the first request (the manager connects eagerly at startup).
	agentArgs := []string{
		"agent",
		"--tunnel-addr", tunnelAddr, "--psk", psk,
		"--auth-pass", authPass, "--priv-pass", privPass,
		"--agent", dev.Addr(), "--community", community,
		"--log-level", "debug",
		"--trap-sink", sink.Addr(),
		"--engine-store", filepath.Join(t.TempDir(), "agent-engine.json"),
	}
	for _, opt := range opts {
		opt(&agentArgs)
	}
	startProxy(t, "agent", agentArgs...)
	waitFront(t, tunnelAddr)

	startProxy(t, "manager",
		"manager",
		"--tunnel-addr", tunnelAddr, "--psk", psk,
		"--auth-pass", authPass, "--priv-pass", privPass,
		"--listen", front, "--community", community,
		"--log-level", "debug",
		"--trap-listen", trapAddr,
		"--engine-store", filepath.Join(t.TempDir(), "manager-engine.json"),
	)
	waitFront(t, front)
	waitFront(t, trapAddr)
	// A bound port is not a working tunnel: wait for an answer end to end.
	waitV2cReady(t, front)

	return &chainFixture{Front: front, TrapAddr: trapAddr, Device: dev, Sink: sink}
}

func randomPSK(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("conformance: psk: %v", err)
	}
	return hex.EncodeToString(key)
}

// TestTranslateChainRequests is the classic two-proxy claim: an untouched
// legacy manager keeps working, in v1 and v2c, across a secured segment.
func TestTranslateChainRequests(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startChain(t, testkit.AgentOptions{})

		req := func(version string, verb Verb, oids ...string) Request {
			return Request{
				Verb: verb, Version: version, Community: community,
				Target: f.Front, OIDs: oids, Timeout: 2, Retries: 1,
			}
		}

		for _, version := range []string{"1", "2c"} {
			version := version
			t.Run("v"+version+"/get", func(t *testing.T) {
				res := mustRun(t, p, req(version, VerbGet, sysDescr))
				requireOK(t, res)
				requireVarbind(t, res, sysDescr, "", "testkit fake agent")
			})

			t.Run("v"+version+"/getnext", func(t *testing.T) {
				res := mustRun(t, p, req(version, VerbGetNext, sysDescr))
				requireOK(t, res)
				requireVarbind(t, res, "1.3.6.1.2.1.1.2.0", "", "")
			})

			t.Run("v"+version+"/set", func(t *testing.T) {
				before := f.Device.SETs()
				r := req(version, VerbSet)
				r.Varbinds = []string{"1.3.6.1.4.1.99.1.1.0=int:7"}
				res := mustRun(t, p, r)
				requireOK(t, res)
				if got := f.Device.SETs(); got != before+1 {
					t.Fatalf("device saw %d SET(s), want %d", got, before+1)
				}
			})

			t.Run("v"+version+"/trap", func(t *testing.T) {
				const trapOID = "1.3.6.1.4.1.99.3.1"
				res := mustRun(t, p, Request{
					Verb: VerbTrap, Version: version, Community: community,
					Target: f.TrapAddr, OIDs: []string{trapOID},
					Varbinds: []string{"1.3.6.1.4.1.99.3.2.0=string:chain"},
					Timeout:  2,
				})
				skipUnsupported(t, res)
				requireOK(t, res)
				// The sink sees a CLEAR v2c notification again: the
				// secured segment is invisible to the real manager, and
				// the v1 → v2 translation must have happened.
				want := trapOID
				if version == "1" {
					// RFC 2576: enterprise.0.specific.
					want = "1.3.6.1.4.1.99.3.0.1"
				}
				dg := f.Sink.WaitForTrapOID(t, want, 10*time.Second)
				if version != "1" {
					info, err := msg.Peek(dg)
					if err != nil || info.Version != msg.Version2c {
						t.Fatalf("notification delivered to the sink is not v2c: %v (version %d)", err, info.Version)
					}
				}
			})
		}

		t.Run("v2c/getbulk", func(t *testing.T) {
			r := req("2c", VerbGetBulk, "1.3.6.1.2.1.1")
			r.MaxRepetitions = 4
			res := mustRun(t, p, r)
			requireOK(t, res)
			if len(res.Varbinds) < 2 {
				t.Fatalf("getbulk returned %d varbinds: %v", len(res.Varbinds), res.Varbinds)
			}
		})

		t.Run("inform-round-trip-through-both-proxies", func(t *testing.T) {
			// The confirmation has to survive four hops: vendor → manager
			// proxy → tunnel → agent proxy → sink, and all the way back.
			// This is the path that had a silent dead end once already.
			before := f.Sink.Count()
			res := mustRun(t, p, Request{
				Verb: VerbInform, Version: "2c", Community: community,
				Target: f.TrapAddr, OIDs: []string{"1.3.6.1.4.1.99.4.1"},
				Timeout: 3, Retries: 1,
			})
			skipUnsupported(t, res)
			if !res.OK {
				t.Fatalf("inform not confirmed by the vendor (kind=%q); the sink received %d notification(s) — "+
					"0 means the proxy never relayed it, >0 means the confirmation did not get back",
					res.ErrorKind, f.Sink.Count()-before)
			}
			if f.Sink.Count() <= before {
				t.Fatalf("sink saw no relayed inform (count %d -> %d)", before, f.Sink.Count())
			}
		})
	})
}

// TestTranslateChainAgentWritePolicy pins defense in depth: the box next to
// the device refuses writes itself, so a compromised manager side cannot
// write even though its own policy allowed the request. The refusal must
// also be ANSWERED through the tunnel, not dropped: the manager has to see
// notWritable instead of retransmitting into a timeout.
func TestTranslateChainAgentWritePolicy(t *testing.T) {
	eachPeer(t, func(t *testing.T, p Peer) {
		f := startChain(t, testkit.AgentOptions{}, withAgentPolicy("--read-only"))

		t.Run("set-refused-at-the-device-side", func(t *testing.T) {
			start := time.Now()
			r := Request{
				Verb: VerbSet, Version: "2c", Community: community,
				Target: f.Front, Timeout: 3, Retries: 1,
				Varbinds: []string{"1.3.6.1.4.1.99.1.1.0=int:9"},
			}
			res := mustRun(t, p, r)
			requireRefused(t, res, KindStatus)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("refusal took %s: the answer did not come back through the tunnel", elapsed)
			}
			if got := f.Device.SETs(); got != 0 {
				t.Fatalf("device saw %d SET(s): the agent-side policy did not hold", got)
			}
		})

		t.Run("reads-still-work", func(t *testing.T) {
			requireOK(t, mustRun(t, p, Request{
				Verb: VerbGet, Version: "2c", Community: community,
				Target: f.Front, OIDs: []string{sysDescr}, Timeout: 2, Retries: 1,
			}))
			if f.Device.GETs() == 0 {
				t.Fatal("read did not reach the device")
			}
		})
	})
}
