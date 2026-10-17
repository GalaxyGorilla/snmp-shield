// translate_agent.go: agent-side USM translate mode. This proxy instance
// is the AUTHORITATIVE engine: managers send SNMPv3 (authPriv) requests to
// the tunnel; the agent side authenticates/decrypts them, converts the
// inner PDU to v1/v2c toward the real agent, converts the response back
// into a v3 response signed+encrypted for the manager, and handles
// engine discovery + timeliness (RFC 3414) with reports.
package usm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kattelma/snmp-proxy/internal/cache"
	"github.com/kattelma/snmp-proxy/internal/config"
	"github.com/kattelma/snmp-proxy/internal/msg"
	"github.com/kattelma/snmp-proxy/internal/observ"
	"github.com/kattelma/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// frame types on the tunnel (mirror of tunnel.Type* constants).
const (
	msgTypeREQ   = 1
	msgTypeRESP  = 2
	msgTypeNOTIF = 3
)

// Errors.
var (
	ErrUnknownUser    = errors.New("usm: unknown user")
	ErrUnknownEngine  = errors.New("usm: unknown engine id")
	ErrNotInTime      = errors.New("usm: message not in time window")
	ErrBadAuth        = errors.New("usm: wrong digest")
	ErrNoPending      = errors.New("usm: no pending request for response")
	ErrUnsupportedSec = errors.New("usm: unsupported security level requested")
)

// Profile is one configured USM user.
type Profile struct {
	Name           string
	AuthProtocol   AuthProtocol
	AuthPassphrase string
	PrivProtocol   PrivProtocol
	PrivPassphrase string
	// Community (agent side) is the v1/v2c community used toward the real
	// agent for requests authenticated as this user.
	Community string
}

// Profiles compiles configured users into derived keys.
type Profiles struct {
	byName map[string]*compiled
}

type compiled struct {
	p        Profile
	authKey  []byte
	privKey  []byte
	engineID []byte // engine the keys are localized for
}

// NewProfiles compiles users against an engine ID (keys are localized per
// engine).
func NewProfiles(users []Profile, engineID []byte) (*Profiles, error) {
	p := &Profiles{byName: make(map[string]*compiled, len(users))}
	for _, u := range users {
		c := &compiled{p: u, engineID: engineID}
		if u.AuthProtocol != AuthNone {
			key, err := PasswordToKey(u.AuthProtocol, u.AuthPassphrase, string(engineID))
			if err != nil {
				return nil, fmt.Errorf("usm: user %s auth key: %w", u.Name, err)
			}
			c.authKey = key
		}
		if u.PrivProtocol != PrivNone {
			key, err := LocalizedPrivKey(u.AuthProtocol, u.PrivProtocol, u.PrivPassphrase, string(engineID))
			if err != nil {
				return nil, fmt.Errorf("usm: user %s priv key: %w", u.Name, err)
			}
			c.privKey = key
		}
		p.byName[u.Name] = c
	}
	return p, nil
}

// Lookup finds a user by name.
func (ps *Profiles) Lookup(name string) (*compiled, bool) {
	c, ok := ps.byName[name]
	return c, ok
}

// FrameSink is the subset of the tunnel Session used by the translators.
type FrameSink interface {
	Send(ctx context.Context, typ, flags uint8, corrID uint16, payload []byte) error
	Subscribe(ftype uint8) (<-chan *tunnel.Frame, func())
}

// AgentTranslator is the agent-side USM translation engine. It terminates
// SNMPv3 from the tunnel (authoritative engine), speaks v1/v2c to the real
// agent over UDP, and owns engine discovery + timeliness.
type AgentTranslator struct {
	translatorBase

	cfg   config.AgentRole
	prof  *Profiles
	clock *cache.EngineClock
	sess  FrameSink
	log   *zap.Logger
	met   *observ.Metrics

	msgID atomic.Uint32

	// pending v3 requests: tunnel corrID -> state
	pendMu sync.Mutex
	pend   map[uint16]*agentPending

	// clear-leg UDP socket toward the real agent
	agentConn net.PacketConn
	stop      chan struct{}
}

// agentPending is one in-flight v3 request (by tunnel corrID).
type agentPending struct {
	tunnelCorrID uint16 // tunnel frame correlation id
	downReqID    int32  // req-id written to the real agent (match key)
	clientReqID  int32  // req-id from the decrypted v3 PDU (echoed back)
	msgID        int32  // v3 msgID echoed in responses
	flags        byte   // requested security level flags
	user         string
	cancel       chan struct{}
}

// NewAgentTranslator builds the agent-side translator.
func NewAgentTranslator(cfg config.AgentRole, users []Profile, clock *cache.EngineClock, sess FrameSink, log *zap.Logger, met *observ.Metrics) (*AgentTranslator, error) {
	prof, err := NewProfiles(users, clock.EngineID())
	if err != nil {
		return nil, err
	}
	return &AgentTranslator{
		translatorBase: translatorBase{
			keys:   newKeyCache(users),
			replay: newReplayCache(),
		},
		cfg:   cfg,
		prof:  prof,
		clock: clock,
		sess:  sess,
		log:   log,
		met:   met,
		pend:  make(map[uint16]*agentPending),
		stop:  make(chan struct{}),
	}, nil
}

// Run starts the translator: subscribes to tunnel REQ frames, binds the
// clear agent socket, and serves until done is closed.
func (a *AgentTranslator) Run(done <-chan struct{}) error {
	// clear UDP socket toward the real agent (ephemeral local port)
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("usm agent: clear socket: %w", err)
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

// handleTunnelRequest processes one v3 request frame from the tunnel.
func (a *AgentTranslator) handleTunnelRequest(f *tunnel.Frame) {
	m, err := msg.ParseV3(f.Payload)
	if err != nil {
		a.log.Debug("usm agent: undecodable v3 from tunnel", zap.Error(err))
		return
	}
	hdr := m.Header

	// engine ID check: must be ours
	if string(m.USM.EngineID) != string(a.clock.EngineID()) {
		a.dropOrReport(hdr, m, f.CorrID, ErrUnknownEngine)
		return
	}
	// timeliness (RFC 3414 3.2 step 4)
	if err := a.clock.AcceptInbound(m.USM.Boots, m.USM.Time); err != nil {
		a.dropOrReport(hdr, m, f.CorrID, ErrNotInTime)
		return
	}

	c, ok := a.prof.Lookup(m.USM.UserName)
	if !ok {
		a.dropOrReport(hdr, m, f.CorrID, ErrUnknownUser)
		return
	}

	// security level enforcement
	wantAuth := hdr.MsgFlags&msg.MsgFlagAuth != 0
	wantPriv := hdr.MsgFlags&msg.MsgFlagPriv != 0
	if wantAuth && c.p.AuthProtocol == AuthNone {
		a.dropOrReport(hdr, m, f.CorrID, ErrUnsupportedSec)
		return
	}
	if wantPriv && c.p.PrivProtocol == PrivNone {
		a.dropOrReport(hdr, m, f.CorrID, ErrUnsupportedSec)
		return
	}

	// authentication: verify digest (zeroed params) when flag set
	if wantAuth {
		off, ok2 := locateAuthParams(f.Payload, m)
		if !ok2 {
			a.dropOrReport(hdr, m, f.CorrID, ErrBadAuth)
			return
		}
		if err := Verify(c.p.AuthProtocol, f.Payload, c.authKey, m.USM.AuthParams, off); err != nil {
			a.dropOrReport(hdr, m, f.CorrID, ErrBadAuth)
			return
		}
	}

	// privacy: decrypt scopedPDU when flag set
	if wantPriv {
		ct, err := scopedCiphertext(m.PDU)
		if err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
			return
		}
		plain, err := decryptScoped(c.p.PrivProtocol, c.privKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, ct)
		if err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
			return
		}
		// UnwrapScopedPDU splits the plaintext scopedPDU TLV into
		// context + PDU and stores the raw PDU TLV in m.PDU.
		if err := m.UnwrapScopedPDU(plain); err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
			return
		}
	} else {
		// plaintext scopedPDU: split context + PDU
		content, err := scopedContent(m.PDU)
		if err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
			return
		}
		if err := m.UnwrapScopedPDU(content); err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
			return
		}
	}
	pduBytes := m.PDU

	// convert v3 PDU -> v1/v2c toward the real agent
	ver, community := a.downstreamFor(c)
	pduType := pduBytes[0]
	// GetBulk unsupported on v1: downgrade to GetNext per RFC 2576 4.1.1
	if ver == msg.Version1 && pduType == msg.PDUGetBulkRequest {
		pduType = msg.PDUGetNextRequest
	}

	downReqID := int32(a.msgID.Add(1))
	downFields, downOK := pduCommon(pduBytes)
	if !downOK {
		a.dropOrReport(hdr, m, f.CorrID, errors.New("usm agent: malformed PDU"))
		return
	}
	pend := &agentPending{
		tunnelCorrID: f.CorrID,
		downReqID:    downReqID,
		clientReqID:  downFields.ReqID,
		msgID:        int32(hdr.MsgID),
		flags:        hdr.MsgFlags,
		user:         m.USM.UserName,
		cancel:       make(chan struct{}),
	}
	a.pendMu.Lock()
	a.pend[f.CorrID] = pend
	a.pendMu.Unlock()

	pdu := msg.BuildPDU(pduType, downReqID, downFields.ErrStatus, downFields.ErrIndex, downFields.Varbinds)
	dg, err := msg.BuildV1V2c(ver, []byte(community), pdu)
	if err != nil {
		a.dropOrReport(hdr, m, f.CorrID, err)
		return
	}

	// ship over the clear leg
	udpAddr, err := net.ResolveUDPAddr("udp", a.cfg.AgentAddr)
	if err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
		return
	}
	if _, err := a.agentConn.WriteTo(dg, udpAddr); err != nil {
			a.dropOrReport(hdr, m, f.CorrID, err)
		return
	}
	if a.met != nil {
		a.met.ReqForwarded.Inc()
	}

	// response timeout: clean up pending
	go func() {
		select {
		case <-time.After(15 * time.Second):
			a.pendMu.Lock()
			if a.pend[pend.tunnelCorrID] == pend {
				delete(a.pend, pend.tunnelCorrID)
			}
			a.pendMu.Unlock()
		case <-pend.cancel:
		}
	}()
}

// readClear reads responses from the real agent on the clear leg.
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

// handleClearResponse converts a v1/v2c agent response into a v3 response
// for the manager and ships it over the tunnel.
func (a *AgentTranslator) handleClearResponse(dg []byte) {
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		a.log.Debug("usm agent: undecodable response from agent", zap.Error(err))
		return
	}
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsGetResponse(info.PDUType) {
		return
	}

	// find pending by the req-id we sent downstream
	a.pendMu.Lock()
	var pend *agentPending
	for _, p := range a.pend {
		if p.downReqID == info.RequestID {
			pend = p
			break
		}
	}
	if pend == nil {
		a.pendMu.Unlock()
		return
	}
	delete(a.pend, pend.tunnelCorrID)
	a.pendMu.Unlock()
	close(pend.cancel)

	c, ok := a.prof.Lookup(pend.user)
	if !ok {
		return
	}

	if err := a.buildAndSendResponse(pend, c, pdu); err != nil {
			a.log.Debug("usm agent: response build failed", zap.Error(err))
	}
}

// buildAndSendResponse wraps a clear v1/v2c PDU into a signed+encrypted v3
// response for the manager side.
func (a *AgentTranslator) buildAndSendResponse(pend *agentPending, c *compiled, pdu []byte) error {
	respFields, respOK := pduCommon(pdu)
	if !respOK {
		return errors.New("usm agent: undecodable PDU in agent response")
	}
	// response PDU: same type, client's req-id, error fields preserved
	resp := msg.BuildPDU(msg.PDUGetResponse, pend.clientReqID, respFields.ErrStatus, respFields.ErrIndex, respFields.Varbinds)

	flags := pend.flags | msg.MsgFlagReportable
	engineID := a.clock.EngineID()
	boots := a.clock.Boots()
	etime := a.clock.Time()

	var authParams []byte
	var privParams []byte
	if pend.flags&msg.MsgFlagAuth != 0 {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}
	if pend.flags&msg.MsgFlagPriv != 0 {
		if c.p.PrivProtocol == PrivDES {
			privParams = a.salt.NextDES(boots)
		} else {
			privParams = a.salt.NextAES()
		}
	}

	scoped := msg.BuildScoped(engineID, []byte{}, resp)

	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, privParams, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      pend.msgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   engineID,
		Boots:      boots,
		Time:       etime,
		UserName:   pend.user,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, encrypt)
	if err != nil {
		return err
	}

	if pend.flags&msg.MsgFlagAuth != 0 {
		if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
			return err
		}
	}

	if err := a.sess.Send(context.Background(), tunnel.TypeRESP, 0, pend.tunnelCorrID, out); err != nil {
			return err
	}
	if a.met != nil {
		a.met.ReqForwarded.Inc()
	}
	return nil
}

// downstreamFor returns the SNMP version + community toward the real agent.
func (a *AgentTranslator) downstreamFor(c *compiled) (int, string) {
	if c.p.Community != "" {
		return msg.Version2c, c.p.Community
	}
	return msg.Version2c, "public"
}

// dropOrReport logs the drop and, when the request was reportable, sends a
// Report PDU (0xA8) back over the tunnel carrying the security error.
// Per RFC 3414 §4 the report is signed with the requesting user when the
// request carried auth; managers (and gosnmp) verify the digest.
func (a *AgentTranslator) dropOrReport(hdr msg.V3Header, m *msg.V3Message, corrID uint16, cause error) {
	if a.met != nil {
		a.met.DropTotal.Inc()
	}
	if hdr.MsgFlags&msg.MsgFlagReportable == 0 {
		a.log.Debug("usm agent: drop", zap.Error(cause))
		return
	}
	// report request-id = triggering msgID; varbind carries the counter
	// for the failure (RFC 3414 usmStats).
	oid := usmStatsOIDFor(cause)
	engineID := a.clock.EngineID()
	pdu := msg.BuildPDU(msg.PDUReport, int32(hdr.MsgID), 0, 0, reportVarbinds(oid))
	scoped := msg.BuildScoped(engineID, []byte{}, pdu)

	var c *compiled
	var userName string
	wantAuth := hdr.MsgFlags&msg.MsgFlagAuth != 0
	if wantAuth && m != nil {
		if cc, ok := a.prof.Lookup(m.USM.UserName); ok {
			c = cc
			userName = m.USM.UserName
		}
	}
	var authParams []byte
	if c != nil {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}
	flags := msg.MsgFlagReportable
	if c != nil {
		flags |= msg.MsgFlagAuth
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      hdr.MsgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   byte(flags),
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   engineID,
		Boots:      a.clock.Boots(),
		Time:       a.clock.Time(),
		UserName:   userName,
		AuthParams: authParams,
	}, scoped, nil)
	if err != nil {
		return
	}
	if c != nil {
		if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
			return
		}
	}
	// response to a tunnel request: correlated via the frame corrID
	_ = a.sess.Send(context.Background(), tunnel.TypeRESP, 0, corrID, out)
}

// handleTunnelNotif processes one inbound v3 trap/inform frame from the
// tunnel (the manager side originates these for its local traps).
func (a *AgentTranslator) handleTunnelNotif(f *tunnel.Frame) {
	m, err := msg.ParseV3(f.Payload)
	if err != nil {
		a.log.Debug("usm agent: undecodable v3 notif", zap.Error(err))
		return
	}
	c, plainPDU, err := a.receiveNotif(f.Payload, m)
	if err != nil {
		a.log.Debug("usm agent: notif rejected", zap.Error(err))
		return
	}
	// deliver to the local sink as v2c (when configured)
	if a.cfg.TrapSinkAddr != "" {
		dg, berr := msg.BuildV1V2c(msg.Version2c, []byte(a.trapCommunity()), plainPDU)
		if berr == nil {
			if serr := sendUDP(a.cfg.TrapSinkAddr, dg); serr != nil {
				a.log.Warn("usm agent: trap sink delivery failed", zap.Error(serr))
			} else if a.met != nil {
				a.met.NotifsRelayed.Inc()
			}
		}
	}
	if len(m.PDU) > 0 && m.PDU[0] == msg.PDUInformRequest {
		a.sendInformResponse(m, plainPDU, c, f.CorrID)
	}
}

// sendInformResponse answers an inform with a GetResponse v3 message
// echoing the inform's USM parameters.
func (a *AgentTranslator) sendInformResponse(m *msg.V3Message, pdu []byte, c *compiled, corrID uint16) {
	if c == nil {
		return
	}
	ifFields, ifOK := pduCommon(pdu)
	var resp []byte
	if ifOK {
		resp = msg.BuildPDU(msg.PDUGetResponse, ifFields.ReqID, 0, 0, ifFields.Varbinds)
	} else {
		resp = msg.BuildPDU(msg.PDUGetResponse, 0, 0, 0, []byte{0})
	}
	flags := m.Header.MsgFlags | msg.MsgFlagReportable
	var authParams []byte
	var privParams []byte
	if m.Header.MsgFlags&msg.MsgFlagAuth != 0 {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}
	if m.Header.MsgFlags&msg.MsgFlagPriv != 0 {
		if c.p.PrivProtocol == PrivDES {
			privParams = a.salt.NextDES(m.USM.Boots)
		} else {
			privParams = a.salt.NextAES()
		}
	}
	scoped := msg.BuildScoped(m.ContextEngineID, []byte{}, resp)
	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, m.USM.Boots, m.USM.Time, privParams, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      m.Header.MsgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   m.USM.EngineID,
		Boots:      m.USM.Boots,
		Time:       m.USM.Time,
		UserName:   m.USM.UserName,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, encrypt)
	if err != nil {
		return
	}
	if m.Header.MsgFlags&msg.MsgFlagAuth != 0 {
		_ = signV3(out, c.p.AuthProtocol, c.authKey)
	}
	_ = a.sess.Send(context.Background(), tunnel.TypeRESP, tunnel.FlagInform, corrID, out)
}

// trapCommunity is the v1/v2c community used in notifications delivered to
// the local trap sink (agent side).
func (a *AgentTranslator) trapCommunity() string {
	if a.cfg.TrapSinkCommunity != "" {
		return a.cfg.TrapSinkCommunity
	}
	return "public"
}

// sendUDP is a best-effort one-shot UDP send (lazy dial per datagram).
func sendUDP(addr string, dg []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(dg)
	return err
}
