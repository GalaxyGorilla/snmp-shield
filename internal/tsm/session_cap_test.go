// session_cap_test.go — the TSM gateway's front-leg session cap.
//
// The raw DTLS front leg is the most exposed surface in the product: it
// accepts connections from any peer before any authentication happens (the
// TLS handshake IS the authentication). Without a cap, a peer that opens
// many client ports can pin one goroutine and one pion FSM each until the
// session dies. The cap closes the door at a fixed count.
package tsm_test

import (
	"context"
	"net"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/tsm"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// buildCappedTSMGateway is buildTSMGateway with an explicit session cap and
// an observable metrics set.
func buildCappedTSMGateway(t *testing.T, ca, serverCrt, serverKey, agentAddr string, maxSessions int) (front string, met *observ.Metrics, stop func()) {
	t.Helper()
	front = freeUDPPort(t)
	cfg := config.GatewayRole{
		ListenAddr:     front,
		AgentAddr:      agentAddr,
		AgentCommunity: "realcomm",
	}
	sec := config.Security{Mode: "tsm-gateway", TSMIdentities: []string{"snmp-shield-manager"}}
	lcfg := tunnel.ListenerConfig{Mode: "dtls", CAFile: ca, CertFile: serverCrt, KeyFile: serverKey}

	met = observ.NewMetrics()
	gw, err := tsm.NewTSMGateway(cfg, sec, lcfg, maxSessions, zap.NewNop(), met)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = gw.Run(done) }()
	return front, met, func() { close(done) }
}

// tryDial attempts a front-leg handshake with a short bound; it returns the
// conn on success (caller closes).
func tryDial(t *testing.T, front, ca, clientCrt, clientKey string, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	d := &tunnel.Dialer{
		Mode:     "dtls",
		CAFile:   ca,
		CertFile: clientCrt,
		KeyFile:  clientKey,
		Timeout:  timeout,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	return d.Dial(ctx, front)
}

// TestTSMGatewaySessionCap: with max_sessions=1, a second concurrent client
// is refused, the refusal is counted, and the slot is reusable afterwards.
func TestTSMGatewaySessionCap(t *testing.T) {
	ca, serverCrt, serverKey, clientCrt, clientKey := certFiles(t)
	fake, agentAddr := fakeAgentOnFreePort(t)
	defer fake.Close()

	front, met, stop := buildCappedTSMGateway(t, ca, serverCrt, serverKey, agentAddr, 1)
	defer stop()
	waitFrontBound(t, front)

	first, err := tryDial(t, front, ca, clientCrt, clientKey, 10*time.Second)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}

	// The second session has no slot: the gateway closes the accepted conn
	// without ever reading the ClientHello, so the handshake never finishes.
	start := time.Now()
	second, err := tryDial(t, front, ca, clientCrt, clientKey, 2*time.Second)
	if err == nil {
		_ = second.Close()
		t.Fatal("second concurrent TSM session was served with max_sessions=1")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("refused session took %s to fail; the cap should fail fast", elapsed)
	}

	var m dto.Metric
	if werr := met.SessionsDenied.Write(&m); werr != nil {
		t.Fatalf("read counter: %v", werr)
	}
	if got := m.GetCounter().GetValue(); got < 1 {
		t.Fatalf("sessions_denied_total = %v, want >= 1", got)
	}

	// Releasing the slot must let the next client in (a cap that never
	// recovers would be a self-inflicted outage).
	_ = first.Close()
	var third net.Conn
	for attempt := 0; attempt < 5 && third == nil; attempt++ {
		time.Sleep(300 * time.Millisecond)
		third, err = tryDial(t, front, ca, clientCrt, clientKey, 5*time.Second)
	}
	if third == nil {
		t.Fatalf("no TSM session accepted after the slot was released: %v", err)
	}
	_ = third.Close()
}
