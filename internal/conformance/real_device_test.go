package conformance

// The clear device leg, judged by a real agent.
//
// The scenarios here exist because every other device-facing assertion in this
// package points the proxy at testkit's own agent: honest semantics, but an
// oracle we wrote against the same `msg` package that produces the requests.
// `TestUSMGatewayRealDevice` puts a real net-snmp `snmpd` behind the gateway,
// so our rebuilt v2c request, the response parsing on the way back, and a SET
// that has to actually land in a third-party MIB are all judged outside the
// tree. `TestUSMGatewayRealDeviceNotifications` closes the other half: the
// device-originated notification path, where `informsink` makes the sender
// strict — net-snmp retransmits an unconfirmed inform once a second, so a
// relay without a working confirmation is six datagrams instead of one.

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// coldStartOID is the notification a net-snmp agent fires at startup
// (snmpTraps.1, RFC 1215). It is the only notification a fixture agent sends
// on its own, which makes it the natural device-originated event.
const coldStartOID = "1.3.6.1.6.3.1.1.5.1"

// TestUSMGatewayRealDevice drives the gateway's clear back leg against a REAL
// v2c agent: what the proxy rebuilds from an authenticated v3 request must be
// acceptable to net-snmp, and a real MIB's answers (walk, bulk, exception,
// writable scalar) must survive the way back.
func TestUSMGatewayRealDevice(t *testing.T) {
	for _, dev := range deviceFixtures() {
		dev := dev
		t.Run(dev.name, func(t *testing.T) {
			agent := dev.start(t, deviceOptions{})
			waitV2cDevice(t, agent.Addr())

			eachPeer(t, func(t *testing.T, p Peer) {
				f := startUSMGatewayOn(t, p, agent.Addr())

				t.Run("get", func(t *testing.T) {
					res := mustRun(t, p, f.v3(VerbGet, sysDescr))
					requireOK(t, res)
					if len(res.Varbinds) != 1 {
						t.Fatalf("got %d varbinds, want 1: %v", len(res.Varbinds), res.Varbinds)
					}
					if got := trimDot(res.Varbinds[0].OID); got != sysDescr {
						t.Fatalf("answer OID = %s, want %s", got, sysDescr)
					}
					if res.Varbinds[0].Value == "" {
						t.Fatalf("sysDescr came back empty: %+v", res.Varbinds[0])
					}
				})

				t.Run("getnext", func(t *testing.T) {
					// A real agent's successor of sysDescr.0 is sysObjectID.0.
					res := mustRun(t, p, f.v3(VerbGetNext, sysDescr))
					requireOK(t, res)
					requireVarbind(t, res, "1.3.6.1.2.1.1.2.0", "", "")
				})

				t.Run("walk", func(t *testing.T) {
					// The system group of a real MIB: a walk that returns one
					// varbind per request would still "pass" a GETNEXT-shaped
					// assertion, so require several and the first one.
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

				t.Run("set-lands-in-the-real-mib", func(t *testing.T) {
					// The write has to be visible on a subsequent READ through
					// the same proxy: "the device saw a SET" is a claim about
					// our fake agent, and a re-encoded write that the real
					// agent rejects would still satisfy it.
					const sysLocation = "1.3.6.1.2.1.1.6.0"
					value := fmt.Sprintf("snmp-shield-%s-%d", p.Name(), time.Now().UnixNano())
					req := f.v3(VerbSet)
					req.Varbinds = []string{sysLocation + "=string:" + value}
					res := mustRun(t, p, req)
					requireOK(t, res)

					read := mustRun(t, p, f.v3(VerbGet, sysLocation))
					requireOK(t, read)
					requireVarbind(t, read, sysLocation, "", value)
				})

				t.Run("missing-object-is-an-exception", func(t *testing.T) {
					// Vendors surface noSuchObject differently (a value or a
					// varbind error); the property that matters is that the
					// proxy answered instead of hanging.
					res := mustRun(t, p, f.v3(VerbGet, "1.3.6.1.4.1.99999.1.0"))
					if res.OK {
						if len(res.Varbinds) != 1 {
							t.Fatalf("want one exception varbind, got %v", res.Varbinds)
						}
						kind := res.Varbinds[0].Type
						if !containsFold(kind, "nosuch") && !containsFold(res.Varbinds[0].Value, "no such") {
							t.Fatalf("want a noSuch* answer, got %+v", res.Varbinds[0])
						}
						return
					}
					if res.ErrorKind != KindStatus {
						t.Fatalf("want an exception/status, got kind=%q: %s", res.ErrorKind, res.Error)
					}
				})
			})
		})
	}
}

// TestUSMGatewayRealDeviceNotifications makes a REAL agent originate the
// notification: `informsink` sends the startup coldStart and retransmits until
// it is confirmed. A real snmptrapd receiver makes the complete path
// third-party on both ends and logs every accepted notification.
func TestUSMGatewayRealDeviceNotifications(t *testing.T) {
	const engineID = "800000000000000000000003"
	trapd := startTrapd(t, engineID)

	for _, dev := range deviceFixtures() {
		dev := dev
		for _, kind := range []struct {
			name   string
			inform bool
		}{
			{"inform", true},
			{"trap", false},
		} {
			kind := kind
			t.Run(dev.name+"/"+kind.name, func(t *testing.T) {
				before := countTrapdOID(trapd.logs(), coldStartOID)
				// Bind the wildcard so the containerised device can reach it
				// (a container cannot dial the host's 127.0.0.1); the probe
				// uses loopback, where the wildcard is reachable too.
				bind := testkit.FreeUDPPort(t, "[::]")
				_, port, err := net.SplitHostPort(bind)
				if err != nil {
					t.Fatalf("bind address %q: %v", bind, err)
				}
				probe := net.JoinHostPort("127.0.0.1", port)

				// Notification-only usm-gateway: no request leg at all, which
				// is a documented deployment shape (protect the manager leg).
				proc := startProxy(t, "usm-gateway-notifications",
					"gateway", "--security", "usm-gateway",
					"--trap-listen", bind, "--trap-sink", trapd.Addr,
					"--auth-pass", authPass, "--priv-pass", privPass,
					"--engine-id", engineID,
				)
				proc.waitFront(t, probe)

				agent := dev.start(t, deviceOptions{
					NotifyAddr: dev.target(bind),
					Inform:     kind.inform,
				})
				waitV2cDevice(t, agent.Addr())

				waitForTrapdOIDCount(t, trapd, coldStartOID, before+1, 20*time.Second)
				if !kind.inform {
					return // traps are fire-and-forget; delivery is the whole claim
				}
				// net-snmp retransmits an unconfirmed inform once a second.
				// Three seconds without a second receiver log proves the
				// confirmation reached the real sender.
				time.Sleep(3 * time.Second)
				if got := countTrapdOID(trapd.logs(), coldStartOID); got != before+1 {
					t.Fatalf("snmptrapd logged %d new coldStart informs, want 1: "+
						"the confirmation did not stop net-snmp retransmitting", got-before)
				}
			})
		}
	}
}

func countTrapdOID(logs, oid string) int {
	return strings.Count(logs, "OID: ."+oid)
}

func waitForTrapdOIDCount(t *testing.T, trapd *trapdFixture, oid string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if countTrapdOID(trapd.logs(), oid) >= want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("snmptrapd did not log notification OID %s; receiver log:\n%s", oid, trapd.logs())
}

// containsFold compares vendor wording case-insensitively (one stack says
// "No Such Object", another "noSuchObject").
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
