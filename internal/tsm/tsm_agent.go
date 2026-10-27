// tsm_agent.go: agent-side TSM engine. It accepts tunnel REQ/NOTIF
// frames, validates the tunnel session's peer certificate against the
// configured identities (the handshake IS the authentication), converts
// the PDU to clear v1/v2c toward the real agent, and reverses responses.
// Inbound notifications are delivered to the local trap sink; informs are
// answered.
package tsm

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// peerCertsSource is satisfied by *tunnel.Session: the peer certificate
// chain of the tunnel connection (nil until the handshake completes).
type peerCertsSource interface {
	PeerCerts() []*x509.Certificate
}

// agentPending is one agent-side in-flight request (tunnel corrID ->
// state). downReqID is the req-id written to the real agent (match key);
// clientReq is the client's original req-id (echoed back).
type agentPending struct {
	ready     chan struct{}
	downReqID int32
}

// AgentTranslator is the agent-side TSM engine.
type AgentTranslator struct {
	cfg  config.AgentRole
	sec  config.Security
	sess FrameSink
	log  *zap.Logger
	met  *observ.Metrics
	// access is the write policy for requests arriving over the tunnel:
	// the device-facing box can protect the device itself, independent
	// of the manager-side proxy. The client allow-list and rate limit do
	// not apply (tunnel frames carry no client address).
	access *access.Holder

	// identity allow-list (from security.tsm_identities / users)
	allowed []string

	msgID atomic.Int32
	reqID atomic.Int32

	pendMu sync.Mutex
	pend   map[uint16]*agentPending

	agentConn net.PacketConn

	stop chan struct{}
}

// NewAgentTranslator builds the agent-side TSM engine. The identity
// allow-list comes from security.tsm_identities, falling back to the
// configured user names.
func NewAgentTranslator(cfg config.AgentRole, sec config.Security, sess FrameSink, log *zap.Logger, met *observ.Metrics) (*AgentTranslator, error) {
	allowed := sec.TSMIdentities
	if len(allowed) == 0 {
		for _, u := range sec.Users {
			allowed = append(allowed, u.Name)
		}
	}
	return &AgentTranslator{
		cfg:     cfg,
		sec:     sec,
		sess:    sess,
		log:     log,
		met:     met,
		allowed: allowed,
		pend:    make(map[uint16]*agentPending),
		stop:    make(chan struct{}),
	}, nil
}

// SetAccess installs (or replaces) the write policy enforced on requests
// arriving over the tunnel. The policy is read per request, so a reload
// takes effect on the next one.
func (a *AgentTranslator) SetAccess(h *access.Holder) { a.access = h }

// Run serves until done is closed.
func (a *AgentTranslator) Run(done <-chan struct{}) error {
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("tsm agent: clear socket: %w", err)
	}
	a.agentConn = conn
	defer conn.Close()

	reqCh, cancelReq := a.sess.Subscribe(msgTypeREQ)
	defer cancelReq()
	notCh, cancelNotif := a.sess.Subscribe(msgTypeNOTIF)
	defer cancelNotif()

	go a.readClear()

	for {
		select {
		case <-done:
			close(a.stop)
			return nil
		case f, ok := <-reqCh:
			if !ok {
				return nil
			}
			a.handleTunnelRequest(f)
		case f, ok := <-notCh:
			if !ok {
				return nil
			}
			a.handleTunnelNotif(f)
		}
	}
}

// checkPeer validates the tunnel session's peer certificate and returns
// the securityName (leaf CN). By the time frames arrive the handshake has
// completed.
func (a *AgentTranslator) checkPeer() (string, error) {
	src, ok := a.sess.(peerCertsSource)
	if !ok {
		return "", ErrNoCerts
	}
	name, err := securityNameFromCerts(src.PeerCerts())
	if err != nil {
		return "", err
	}
	if !peerOK(name, a.allowed) {
		return "", ErrUnknownPeer
	}
	return name, nil
}

// readClear reads responses from the real agent.
func (a *AgentTranslator) readClear() {
	buf := make([]byte, 65536)
	for {
		n, _, err := a.agentConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-a.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		a.handleClearResponse(dg)
	}
}

// handleTunnelRequest unwraps a TSM request, validates the peer, and
// forwards the PDU to the real agent.
func (a *AgentTranslator) handleTunnelRequest(f *tunnel.Frame) {
	if _, err := a.checkPeer(); err != nil {
		a.log.Warn("tsm agent: peer rejected", zap.Error(err))
		return
	}
	m, err := msg.ParseV3(f.Payload)
	if err != nil {
		a.log.Debug("tsm agent: undecodable v3 from tunnel", zap.Error(err))
		return
	}
	pdu, err := unwrapTSM(m)
	if err != nil {
		a.log.Debug("tsm agent: bad TSM request", zap.Error(err))
		return
	}
	if len(pdu) == 0 || !msg.IsGet(pdu[0]) && !msg.IsGetNext(pdu[0]) &&
		!msg.IsSet(pdu[0]) && !msg.IsGetBulk(pdu[0]) {
		return
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		return
	}

	// Write policy: refuse before anything reaches the device, and answer
	// so the manager does not retransmit into a timeout.
	if !a.access.Get().AllowWrite(pdu) {
		if a.met != nil {
			a.met.WritesDenied.Inc()
		}
		refusal := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, msg.ErrStatusNotWritable, 0, fields.Varbinds)
		out, werr := wrapTSMPDU(a.msgID.Add(1), refusal, nil, msg.MsgFlagReportable, "")
		if werr != nil {
			return
		}
		if werr = a.sess.Send(context.Background(), tunnel.TypeRESP, 0, f.CorrID, out); werr != nil {
			a.log.Debug("tsm agent: notWritable send failed", zap.Error(werr))
		}
		return
	}

	downReqID := a.reqID.Add(1)
	corrID := f.CorrID
	pend := &agentPending{ready: make(chan struct{}), downReqID: downReqID}
	a.pendMu.Lock()
	a.pend[corrID] = pend
	a.pendMu.Unlock()

	down := msg.BuildPDU(pdu[0], downReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	community := a.cfg.AgentCommunity
	if community == "" {
		community = "public"
	}
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte(community), down)
	if err != nil {
		a.dropPending(corrID)
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", a.cfg.AgentAddr)
	if err != nil {
		a.dropPending(corrID)
		return
	}
	if _, err := a.agentConn.WriteTo(dg, udpAddr); err != nil {
		a.dropPending(corrID)
		return
	}
	if a.met != nil {
		a.met.ReqForwarded.Inc()
	}

	go func() {
		select {
		case <-time.After(reqTimeout):
			a.dropPending(corrID)
		case <-pend.ready:
		}
	}()
}

func (a *AgentTranslator) dropPending(corrID uint16) {
	a.pendMu.Lock()
	delete(a.pend, corrID)
	a.pendMu.Unlock()
}

// handleClearResponse wraps a clear agent response into a TSM frame and
// ships it over the tunnel.
func (a *AgentTranslator) handleClearResponse(dg []byte) {
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		a.log.Debug("tsm agent: undecodable response from agent", zap.Error(err))
		return
	}
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsGetResponse(info.PDUType) {
		return
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		return
	}

	// find the pending by the req-id we sent downstream
	a.pendMu.Lock()
	var corrID uint16
	var pend *agentPending
	for id, p := range a.pend {
		if p.downReqID == info.RequestID {
			corrID = id
			pend = p
			break
		}
	}
	if pend == nil {
		a.pendMu.Unlock()
		return
	}
	delete(a.pend, corrID)
	a.pendMu.Unlock()
	close(pend.ready)

	out, err := wrapTSM(a.msgID.Add(1), info.RequestID, msg.PDUGetResponse, fields.Varbinds, nil, msg.MsgFlagReportable, "")
	if err != nil {
		return
	}
	// the response PDU carries the downstream req-id; rebuild with the
	// client's original request semantics preserved via fields
	if err := a.sess.Send(context.Background(), tunnel.TypeRESP, 0, corrID, out); err != nil {
		a.log.Debug("tsm agent: response send failed", zap.Error(err))
	}
}

// handleTunnelNotif delivers inbound notifications to the local trap sink
// and answers informs.
func (a *AgentTranslator) handleTunnelNotif(f *tunnel.Frame) {
	if _, err := a.checkPeer(); err != nil {
		a.log.Warn("tsm agent: peer rejected", zap.Error(err))
		return
	}
	m, err := msg.ParseV3(f.Payload)
	if err != nil {
		return
	}
	pdu, err := unwrapTSM(m)
	if err != nil {
		return
	}
	if len(pdu) == 0 {
		return
	}

	// deliver to the local sink as v2c (when configured)
	if a.cfg.TrapSinkAddr != "" {
		dg, berr := msg.BuildV1V2c(msg.Version2c, []byte(trapCommunity(a.cfg.TrapSinkCommunity)), pdu)
		if berr == nil {
			if serr := sinkWrite(a.cfg.TrapSinkAddr, dg); serr != nil {
				a.log.Warn("tsm agent: trap sink delivery failed", zap.Error(serr))
			} else if a.met != nil {
				a.met.NotifsRelayed.Inc()
			}
		}
	}

	// inform: answer with a GetResponse TSM frame echoing the req-id,
	// securityName and security-level flags (TSM response echo rule)
	if pdu[0] == msg.PDUInformRequest {
		fields, ok := pduCommon(pdu)
		if !ok {
			return
		}
		out, err := wrapTSM(a.msgID.Add(1), fields.ReqID, msg.PDUGetResponse, fields.Varbinds, nil,
			m.Header.MsgFlags|msg.MsgFlagReportable, m.USM.UserName)
		if err != nil {
			return
		}
		_ = a.sess.Send(context.Background(), tunnel.TypeRESP, tunnel.FlagInform, f.CorrID, out)
	}
}
