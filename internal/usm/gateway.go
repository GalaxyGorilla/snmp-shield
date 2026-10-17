// gateway.go: single-box USM gateway role. This proxy instance is the
// AUTHORITATIVE SNMP engine toward standard managers: a plain-UDP front
// leg terminates SNMPv3 USM directly (RFC 3414 discovery Reports,
// persisted engineBoots/engineTime with anti-rollback, the configured
// security.users, timeliness window). Authenticated v3 requests are
// relayed as clear v1/v2c to the legacy agent; clear v1/v2c arriving on
// the front leg is rejected — that rejection is the protection. Clear
// notifications from the legacy network (trap_listen_addr) are wrapped
// into authenticated v3 USM notifications toward the manager's trap
// receiver (trap_sink_addr). No tunnel, no second proxy — 100% standard
// SNMP on every wire.
package usm

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"go.uber.org/zap"
)

// GatewayTranslator is the single-box USM gateway engine: it terminates
// SNMPv3 USM from standard managers on a plain-UDP front leg (this proxy
// is the authoritative engine), relays authenticated requests as clear
// v1/v2c to the legacy agent, and wraps clear notifications into
// authenticated v3 USM notifications toward the manager's trap receiver.
type GatewayTranslator struct {
	translatorBase

	cfg   config.GatewayRole
	prof  *Profiles
	users []Profile
	clock *cache.EngineClock
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	msgID atomic.Uint32

	// pending forwarded requests: req-id written to the agent -> state
	pendMu sync.Mutex
	pend   map[int32]*gwPending

	// front leg (SNMPv3 USM listener), clear agent socket, trap listener
	conn      net.PacketConn
	agentConn net.PacketConn
	trapConn  net.PacketConn
	stop      chan struct{}
}

// gwPending is one in-flight forwarded request.
type gwPending struct {
	addr        net.Addr // manager that sent the v3 request
	clientReqID int32    // req-id from the decrypted v3 PDU (echoed back)
	msgID       int32    // v3 msgID echoed in responses
	flags       byte     // requested security level flags
	user        string
	cancel      chan struct{}
}

// NewGatewayTranslator builds the single-box gateway translator.
func NewGatewayTranslator(cfg config.GatewayRole, users []Profile, clock *cache.EngineClock, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*GatewayTranslator, error) {
	prof, err := NewProfiles(users, clock.EngineID())
	if err != nil {
		return nil, err
	}
	return &GatewayTranslator{
		translatorBase: translatorBase{
			keys:   newKeyCache(users),
			replay: newReplayCache(),
		},
		cfg:   cfg,
		prof:  prof,
		users: users,
		clock: clock,
		log:   log,
		met:   met,
		filtr: notifyfilter.From(filt...),
		pend:  make(map[int32]*gwPending),
		stop:  make(chan struct{}),
	}, nil
}

// Run binds the front leg, the clear agent socket and (optionally) the
// clear trap listener, and serves until done is closed. When supplied, ready
// is closed after every configured listener has been bound.
func (g *GatewayTranslator) Run(done <-chan struct{}, ready ...chan<- struct{}) error {
	conn, err := net.ListenPacket("udp", g.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("usm gateway: front listener: %w", err)
	}
	g.conn = conn
	defer conn.Close()

	agentConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("usm gateway: clear agent socket: %w", err)
	}
	g.agentConn = agentConn
	defer agentConn.Close()

	if g.cfg.TrapListenAddr != "" {
		tconn, terr := net.ListenPacket("udp", g.cfg.TrapListenAddr)
		if terr != nil {
			return fmt.Errorf("usm gateway: trap listener: %w", terr)
		}
		g.trapConn = tconn
		defer tconn.Close()
	}

	go g.readFront()
	go g.readAgent()
	if g.trapConn != nil {
		go g.readTraps()
	}
	if len(ready) > 0 && ready[0] != nil {
		close(ready[0])
	}

	<-done
	close(g.stop)
	return nil
}

// readFront reads SNMP datagrams from managers on the front leg. Only
// SNMPv3 USM is accepted: clear v1/v2c is rejected — that rejection is
// the gateway's protection of the legacy agent.
func (g *GatewayTranslator) readFront() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := g.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-g.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		info, err := msg.Peek(dg)
		if err != nil {
			g.drop()
			continue
		}
		if info.Version != msg.Version3 {
			g.rejectClear(info.Version)
			continue
		}
		g.handleFrontRequest(addr, dg)
	}
}

// handleFrontRequest processes one SNMPv3 USM request from a manager:
// authenticate + decrypt, then relay the inner PDU as clear v1/v2c to
// the legacy agent.
func (g *GatewayTranslator) handleFrontRequest(addr net.Addr, dg []byte) {
	m, err := msg.ParseV3(dg)
	if err != nil {
		g.drop()
		return
	}
	hdr := m.Header

	// engine ID check: must be ours. An empty engine ID is the RFC 3414
	// discovery probe — answered by our Report below.
	if string(m.USM.EngineID) != string(g.clock.EngineID()) {
		g.dropOrReport(hdr, m, addr, ErrUnknownEngine)
		return
	}
	// timeliness (RFC 3414 3.2 step 5): enforced after digest
	// verification below, so an AUTHENTICATED higher-boots claim can be
	// adopted as a logical reboot (HA pair state sync) instead of being
	// rejected forever.
	timeErr := g.clock.AcceptInbound(m.USM.Boots, m.USM.Time)

	c, ok := g.prof.Lookup(m.USM.UserName)
	if !ok {
		g.dropOrReport(hdr, m, addr, ErrUnknownUser)
		return
	}

	// security level enforcement
	wantAuth := hdr.MsgFlags&msg.MsgFlagAuth != 0
	wantPriv := hdr.MsgFlags&msg.MsgFlagPriv != 0
	if wantAuth && c.p.AuthProtocol == AuthNone {
		g.dropOrReport(hdr, m, addr, ErrUnsupportedSec)
		return
	}
	if wantPriv && c.p.PrivProtocol == PrivNone {
		g.dropOrReport(hdr, m, addr, ErrUnsupportedSec)
		return
	}

	// authentication: verify digest (zeroed params) when flag set.
	// verified stays false for NoAuth messages: they carry no digest, so
	// nothing about them is authenticated (and they must never drive the
	// HA boots adoption below).
	verified := false
	if wantAuth {
		off, ok2 := locateAuthParams(dg, m)
		if !ok2 {
			g.dropOrReport(hdr, m, addr, ErrBadAuth)
			return
		}
		if err := Verify(c.p.AuthProtocol, dg, c.authKey, m.USM.AuthParams, off); err != nil {
			g.dropOrReport(hdr, m, addr, ErrBadAuth)
			return
		}
		verified = true
	}

	// Timeliness AFTER digest verification: a verified HIGHER boots
	// claim is a logical reboot (HA failover with a shared engineID but
	// separate engine stores) — adopt it, re-anchor the engine clock and
	// serve. Any other stale/out-of-window claim is rejected exactly as
	// before. Unverified claims (NoAuthNoPriv, or any failed digest)
	// never adopt: pre-auth rejection and replay protection unchanged.
	if timeErr != nil {
		if verified && m.USM.Boots > g.clock.Boots() {
			g.clock.AdoptInbound(m.USM.Boots, m.USM.Time)
			g.log.Info("usm gateway: adopting higher engine boots (HA failover)",
				zap.Uint32("boots", m.USM.Boots))
		} else {
			g.dropOrReport(hdr, m, addr, ErrNotInTime)
			return
		}
	}

	// privacy: decrypt scopedPDU when flag set
	if wantPriv {
		ct, err := scopedCiphertext(m.PDU)
		if err != nil {
			g.dropOrReport(hdr, m, addr, err)
			return
		}
		plain, err := decryptScoped(c.p.PrivProtocol, c.privKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, ct)
		if err != nil {
			g.dropOrReport(hdr, m, addr, err)
			return
		}
		// UnwrapScopedPDU splits the plaintext scopedPDU TLV into
		// context + PDU and stores the raw PDU TLV in m.PDU.
		if err := m.UnwrapScopedPDU(plain); err != nil {
			g.dropOrReport(hdr, m, addr, err)
			return
		}
	} else {
		// plaintext scopedPDU: split context + PDU
		content, err := scopedContent(m.PDU)
		if err != nil {
			g.dropOrReport(hdr, m, addr, err)
			return
		}
		if err := m.UnwrapScopedPDU(content); err != nil {
			g.dropOrReport(hdr, m, addr, err)
			return
		}
	}
	pduBytes := m.PDU

	// relay the inner PDU as clear v2c toward the legacy agent
	ver, community := g.downstreamFor(c)
	pduType := pduBytes[0]

	downReqID := int32(g.msgID.Add(1))
	downFields, downOK := pduCommon(pduBytes)
	if !downOK {
		g.dropOrReport(hdr, m, addr, errors.New("usm gateway: malformed PDU"))
		return
	}
	pend := &gwPending{
		addr:        addr,
		clientReqID: downFields.ReqID,
		msgID:       int32(hdr.MsgID),
		flags:       hdr.MsgFlags,
		user:        m.USM.UserName,
		cancel:      make(chan struct{}),
	}
	g.pendMu.Lock()
	g.pend[downReqID] = pend
	g.pendMu.Unlock()

	pdu := msg.BuildPDU(pduType, downReqID, downFields.ErrStatus, downFields.ErrIndex, downFields.Varbinds)
	request, err := msg.BuildV1V2c(ver, []byte(community), pdu)
	if err != nil {
		g.dropOrReport(hdr, m, addr, err)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", g.cfg.AgentAddr)
	if err != nil {
		g.dropOrReport(hdr, m, addr, err)
		return
	}
	if _, err := g.agentConn.WriteTo(request, udpAddr); err != nil {
		g.dropOrReport(hdr, m, addr, err)
		return
	}
	if g.met != nil {
		g.met.ReqForwarded.Inc()
	}

	// response timeout: clean up pending
	go func() {
		select {
		case <-time.After(15 * time.Second):
			g.pendMu.Lock()
			if g.pend[downReqID] == pend {
				delete(g.pend, downReqID)
			}
			g.pendMu.Unlock()
		case <-pend.cancel:
		}
	}()
}

// readAgent reads responses from the legacy agent on the clear leg.
func (g *GatewayTranslator) readAgent() {
	buf := make([]byte, 65536)
	for {
		n, _, err := g.agentConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-g.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		g.handleAgentResponse(dg)
	}
}

// handleAgentResponse converts a clear v1/v2c agent response into a
// signed+encrypted v3 response for the originating manager.
func (g *GatewayTranslator) handleAgentResponse(dg []byte) {
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		g.log.Debug("usm gateway: undecodable response from agent", zap.Error(err))
		return
	}
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsGetResponse(info.PDUType) {
		return
	}

	// find the pending request by the req-id we sent downstream
	g.pendMu.Lock()
	pend, ok := g.pend[info.RequestID]
	if !ok {
		g.pendMu.Unlock()
		return
	}
	delete(g.pend, info.RequestID)
	g.pendMu.Unlock()
	close(pend.cancel)

	c, ok := g.prof.Lookup(pend.user)
	if !ok {
		return
	}

	if err := g.buildAndSendResponse(pend, c, pdu); err != nil {
		g.log.Debug("usm gateway: response build failed", zap.Error(err))
	}
}

// buildAndSendResponse wraps a clear v1/v2c PDU into a signed+encrypted
// v3 response for the manager and sends it on the front leg.
func (g *GatewayTranslator) buildAndSendResponse(pend *gwPending, c *compiled, pdu []byte) error {
	respFields, respOK := pduCommon(pdu)
	if !respOK {
		return errors.New("usm gateway: undecodable PDU in agent response")
	}
	// response PDU: same type, manager's req-id, error fields preserved
	resp := msg.BuildPDU(msg.PDUGetResponse, pend.clientReqID, respFields.ErrStatus, respFields.ErrIndex, respFields.Varbinds)

	flags := pend.flags | msg.MsgFlagReportable
	engineID := g.clock.EngineID()
	boots := g.clock.Boots()
	etime := g.clock.Time()

	var authParams []byte
	var privParams []byte
	if pend.flags&msg.MsgFlagAuth != 0 {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}
	if pend.flags&msg.MsgFlagPriv != 0 {
		if c.p.PrivProtocol == PrivDES {
			privParams = g.salt.NextDES(boots)
		} else {
			privParams = g.salt.NextAES()
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

	_, err = g.conn.WriteTo(out, pend.addr)
	if err != nil {
		return err
	}
	if g.met != nil {
		g.met.ReqForwarded.Inc()
	}
	return nil
}

// downstreamFor returns the SNMP version + community toward the legacy
// agent: the user's community, else the gateway-wide community, else
// "public".
func (g *GatewayTranslator) downstreamFor(c *compiled) (int, string) {
	if c.p.Community != "" {
		return msg.Version2c, c.p.Community
	}
	if g.cfg.AgentCommunity != "" {
		return msg.Version2c, g.cfg.AgentCommunity
	}
	return msg.Version2c, "public"
}

// dropOrReport logs the drop and, when the request was reportable, sends
// a Report PDU (0xA8) to the manager carrying the security error. Per
// RFC 3414 §4 the report is signed with the requesting user when the
// request carried auth; managers (and gosnmp) verify the digest. The
// discovery probe (empty engine ID, NoAuthNoPriv) is answered with an
// unsigned report whose USM parameters reveal our engineID/boots/time.
func (g *GatewayTranslator) dropOrReport(hdr msg.V3Header, m *msg.V3Message, addr net.Addr, cause error) {
	if g.met != nil {
		g.met.DropTotal.Inc()
	}
	if hdr.MsgFlags&msg.MsgFlagReportable == 0 {
		g.log.Debug("usm gateway: drop", zap.Error(cause))
		return
	}
	// report request-id = triggering msgID; varbind carries the counter
	// for the failure (RFC 3414 usmStats).
	oid := usmStatsOIDFor(cause)
	engineID := g.clock.EngineID()
	pdu := msg.BuildPDU(msg.PDUReport, int32(hdr.MsgID), 0, 0, reportVarbinds(oid))
	scoped := msg.BuildScoped(engineID, []byte{}, pdu)

	var c *compiled
	var userName string
	wantAuth := hdr.MsgFlags&msg.MsgFlagAuth != 0
	if wantAuth && m != nil {
		if cc, ok := g.prof.Lookup(m.USM.UserName); ok {
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
		Boots:      g.clock.Boots(),
		Time:       g.clock.Time(),
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
	_, _ = g.conn.WriteTo(out, addr)
}

// readTraps reads clear notifications from the legacy network.
func (g *GatewayTranslator) readTraps() {
	buf := make([]byte, 65536)
	for {
		n, _, err := g.trapConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-g.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		g.handleClearTrap(dg)
	}
}

// handleClearTrap wraps a clear v1/v2c notification into an authenticated
// v3 USM notification (first configured user, this gateway's own engine)
// and delivers it to the manager's trap receiver (trap_sink_addr).
func (g *GatewayTranslator) handleClearTrap(dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil {
		return
	}
	if g.filtr != nil && (msg.IsTrap(info.PDUType) || msg.IsInform(info.PDUType)) {
		oid, ok := msg.TrapOID(dg)
		if !ok || !g.filtr.Allowed(oid) {
			if g.met != nil {
				g.met.NotifsFiltered.Inc()
			}
			g.log.Debug("usm gateway: notification filtered", zap.String("trap_oid", oid))
			return
		}
	}
	_, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}

	var pdu []byte
	switch {
	case info.PDUType == msg.PDUTrap:
		// v1 trap: translate parameters to v2 per RFC 2576 3.1
		t, terr := msg.SplitV1Trap(pduTLV)
		if terr != nil {
			return
		}
		vbs, verr := msg.V1TrapToV2(t, community, true)
		if verr != nil {
			return
		}
		pdu = msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vbs)
	default:
		pdu = pduTLV
	}

	out, err := g.buildTrapNotif(pdu)
	if err != nil {
		g.log.Warn("usm gateway: trap wrap failed", zap.Error(err))
		return
	}
	if g.cfg.TrapSinkAddr == "" {
		g.log.Debug("usm gateway: trap dropped (no trap_sink_addr configured)")
		return
	}
	if err := sendUDP(g.cfg.TrapSinkAddr, out); err != nil {
		g.log.Warn("usm gateway: trap sink delivery failed", zap.Error(err))
		return
	}
	if g.met != nil {
		g.met.NotifsRelayed.Inc()
	}
}

// buildTrapNotif builds a signed+encrypted v3 USM notification for the
// manager's trap receiver using the first configured user and this
// gateway's own engine state (no discovery: we are the engine).
func (g *GatewayTranslator) buildTrapNotif(pdu []byte) ([]byte, error) {
	if len(g.users) == 0 {
		return nil, errors.New("usm gateway: no users configured")
	}
	c, ok := g.prof.Lookup(g.users[0].Name)
	if !ok {
		return nil, fmt.Errorf("usm gateway: user %s not found", g.users[0].Name)
	}

	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable)
	engineID := g.clock.EngineID()
	boots := g.clock.Boots()
	etime := g.clock.Time()
	privParams := g.salt.NextAES()
	authParams := make([]byte, c.p.AuthProtocol.MacLength())

	scoped := msg.BuildScoped(engineID, []byte{}, pdu)
	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, privParams, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(g.msgID.Add(1)),
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   engineID,
		Boots:      boots,
		Time:       etime,
		UserName:   g.users[0].Name,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, encrypt)
	if err != nil {
		return nil, err
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		return nil, err
	}
	return out, nil
}

// rejectClear drops clear v1/v2c SNMP arriving on the v3 front leg. This
// rejection is the gateway's protection: unauthenticated traffic never
// reaches the legacy agent.
func (g *GatewayTranslator) rejectClear(ver int) {
	if g.met != nil {
		g.met.DropTotal.Inc()
	}
	g.log.Debug("usm gateway: clear SNMP rejected on v3 front leg", zap.Int("snmp_version", ver))
}

// drop counts and logs an undecodable front-leg datagram.
func (g *GatewayTranslator) drop() {
	if g.met != nil {
		g.met.DropTotal.Inc()
	}
	g.log.Debug("usm gateway: undecodable datagram on front leg")
}
