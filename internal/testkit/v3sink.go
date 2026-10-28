package testkit

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// V3Sink is a manager-side trap receiver that actually speaks SNMPv3 USM:
// it verifies the digest, decrypts the payload and answers informs.
//
// A dumb UDP listener is enough for "did a datagram arrive", but not for
// the questions that matter: is the notification verifiable by an
// independent USM implementation, does it carry the trap OID we expect, and
// is an inform confirmed end to end. Using gosnmp's TrapListener as the sink
// gives all three without hand-rolling USM in the test.
//
// Note: gosnmp re-derives the keys from the engineID on the wire, so it
// works against a proxy that is its own authoritative engine (no discovery
// needed for notifications).
type V3Sink struct {
	Addr string

	mu   sync.Mutex
	trap []*gosnmp.SnmpPacket
	sig  chan struct{}

	listener *gosnmp.TrapListener
}

// V3SinkOptions configures the USM user the sink accepts.
type V3SinkOptions struct {
	// User is the security name (in usm-gateway flags mode this is
	// "proxy", the user the gateway signs its notifications with).
	User string
	// Passphrases must match the sender's.
	AuthPass string
	PrivPass string
	// Level selects authPriv (default), authNoPriv or noAuthNoPriv.
	Level string
}

// NewV3Sink starts a v3 trap receiver on an ephemeral loopback port. It
// answers informs automatically, which is what makes an inform round trip
// observable from the sender's point of view.
func NewV3Sink(t testing.TB, opts V3SinkOptions) *V3Sink {
	t.Helper()
	if opts.Level == "" {
		opts.Level = "authpriv"
	}
	// TrapListener.Listen does not report the bound address back, so a
	// probe-then-bind is the only way to get an ephemeral port here. The
	// window is microseconds; if it ever loses the race the test fails at
	// Listen with a clear bind error rather than flaking silently.
	addr := FreeUDPPort(t, "")

	params := &gosnmp.GoSNMP{
		Version:            gosnmp.Version3,
		SecurityModel:      gosnmp.UserSecurityModel,
		Transport:          "udp",
		Port:               0,
		Timeout:            2 * time.Second,
		Retries:            0,
		ExponentialTimeout: false,
	}
	usm := &gosnmp.UsmSecurityParameters{UserName: opts.User}
	switch opts.Level {
	case "noauthnopriv":
		params.MsgFlags = gosnmp.NoAuthNoPriv
	case "authnopriv":
		params.MsgFlags = gosnmp.AuthNoPriv
		usm.AuthenticationProtocol = gosnmp.SHA
		usm.AuthenticationPassphrase = opts.AuthPass
	default:
		params.MsgFlags = gosnmp.AuthPriv
		usm.AuthenticationProtocol = gosnmp.SHA
		usm.AuthenticationPassphrase = opts.AuthPass
		usm.PrivacyProtocol = gosnmp.AES
		usm.PrivacyPassphrase = opts.PrivPass
	}
	params.SecurityParameters = usm

	s := &V3Sink{Addr: addr, sig: make(chan struct{}, 1)}
	l := gosnmp.NewTrapListener()
	l.Params = params
	l.OnNewTrap = func(packet *gosnmp.SnmpPacket, _ *net.UDPAddr) {
		s.mu.Lock()
		s.trap = append(s.trap, packet)
		s.mu.Unlock()
		select {
		case s.sig <- struct{}{}:
		default:
		}
	}
	s.listener = l
	// Listen blocks until Close, so it runs in its own goroutine; Listening()
	// signals that the socket is actually bound.
	errCh := make(chan error, 1)
	go func() { errCh <- l.Listen(addr) }()
	select {
	case <-l.Listening():
	case err := <-errCh:
		t.Fatalf("testkit: v3 sink listen on %s: %v", addr, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("testkit: v3 sink did not start listening on %s", addr)
	}
	t.Cleanup(l.Close)
	return s
}

// Count is how many notifications the sink accepted (a digest failure means
// gosnmp drops the packet before OnNewTrap, so a rejected message never
// counts).
func (s *V3Sink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.trap)
}

// Traps returns a copy of the accepted notifications.
func (s *V3Sink) Traps() []*gosnmp.SnmpPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*gosnmp.SnmpPacket, len(s.trap))
	copy(out, s.trap)
	return out
}

// WaitForOID blocks until a notification carrying trapOID arrives. The trap
// OID is read from snmpTrapOID.0 exactly as a real manager would, so this
// also asserts that the notification survived the wrap with its payload.
func (s *V3Sink) WaitForOID(t testing.TB, trapOID string, timeout time.Duration) *gosnmp.SnmpPacket {
	t.Helper()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		for _, pkt := range s.Traps() {
			for _, vb := range pkt.Variables {
				if trimLeadingDots(vb.Name) != "1.3.6.1.6.3.1.1.4.1.0" {
					continue
				}
				if got, ok := vb.Value.(string); ok && trimLeadingDots(got) == trimLeadingDots(trapOID) {
					return pkt
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("testkit: v3 sink saw %d notification(s) but none with trap OID %s: %s",
				s.Count(), trapOID, s.describe())
			return nil
		}
		select {
		case <-s.sig:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (s *V3Sink) describe() string {
	seen := make([]string, 0)
	for _, pkt := range s.Traps() {
		for _, vb := range pkt.Variables {
			if trimLeadingDots(vb.Name) == "1.3.6.1.6.3.1.1.4.1.0" {
				seen = append(seen, trimLeadingDots(toStr(vb.Value)))
			}
		}
	}
	return "trap OIDs seen: " + sprintList(seen)
}

func toStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func sprintList(in []string) string {
	out := "["
	for i, s := range in {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out + "]"
}

func trimLeadingDots(s string) string {
	for len(s) > 0 && s[0] == '.' {
		s = s[1:]
	}
	return s
}
