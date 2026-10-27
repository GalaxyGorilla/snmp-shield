// manager_gateway.go: manager-gateway mode (gateway role, security.mode
// usm-manager-gateway). The mirror of the agent-facing usm-gateway: this
// proxy protects a LEGACY manager talking to a V3-CAPABLE agent.
//
//	[legacy manager] --clear v1/v2c--> [this proxy] --v3 USM authPriv--> [real v3 agent]
//
// The clear front leg accepts v1/v2c GET/GETNEXT/GETBULK/SET from the
// legacy manager; every request is wrapped into an authenticated+encrypted
// v3 USM request toward the real agent (the proxy is a v3 command
// GENERATOR here: RFC 3414 discovery against the agent's authoritative
// engine, engineBoots/engineTime tracked with 60s re-discovery, responses
// verified/decrypted with keys localized to the AGENT's engineID from the
// wire). The v3 response is stripped back to clear v1/v2c (req-id echoed,
// original community) and relayed to the manager. Notifications reverse:
// the v3 agent's traps/informs arriving at trap_listen_addr are verified,
// unwrapped and relayed as clear v1/v2c toward the manager's trap
// receiver (trap_sink_addr) — informs are answered directly by this
// proxy (the confirmation terminates here), their payload relayed as a
// clear trap. Unauthenticated v3 traffic (bad digest, stale engine time)
// never reaches the manager.
package usm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"go.uber.org/zap"
)

// ManagerGateway translates between a legacy manager (clear v1/v2c) and
// a v3-capable agent (USM authPriv). The proxy is the v3 command
// generator and the notification verifier.
type ManagerGateway struct {
	translatorBase

	cfg   config.GatewayRole
	sec   config.Security
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	// remote agent engine state (discovered, refreshed)
	engineMu sync.Mutex
	remote   *remoteEngine

	msgID atomic.Uint32
	reqID atomic.Uint32

	// pending agent requests keyed on the v3 msgID we sent
	pendMu sync.Mutex
	pend   map[int32]*mgwPending

	// clear manager-facing socket, agent socket, v3 trap listener
	conn      net.PacketConn
	agentConn net.PacketConn
	trapConn  net.PacketConn
	stop      chan struct{}
}

// mgwPending is one in-flight request toward the v3 agent.
type mgwPending struct {
	managerAddr net.Addr // legacy manager waiting for the response
	ver         int      // original SNMP version (1 or 2c)
	community   []byte   // original clear community
	clientReqID int32    // req-id from the clear request (echoed back)
	resp        []byte   // rebuilt clear response (stashed on match)
	ready       chan struct{}
}

// NewManagerGateway builds the manager-gateway translator. The
// security.users are the AGENT-side v3 credentials (the real agent's
// user database must contain them).
func NewManagerGateway(cfg config.GatewayRole, sec config.Security, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*ManagerGateway, error) {
	users := profilesFromConfig(sec)
	if len(users) == 0 {
		return nil, errors.New("usm manager-gateway: no users configured (agent-side v3 credentials)")
	}
	return &ManagerGateway{
		translatorBase: translatorBase{
			keys:   newKeyCache(users),
			replay: newReplayCache(),
		},
		cfg:   cfg,
		sec:   sec,
		log:   log,
		met:   met,
		filtr: notifyfilter.From(filt...),
		pend:  make(map[int32]*mgwPending),
		stop:  make(chan struct{}),
	}, nil
}

// Run binds the configured legs and serves until done is closed. The
// front leg (ListenAddr) and the v3 trap listener (TrapListenAddr) are
// optional; at least one must be configured. When supplied, ready is
// closed after every configured listener has been bound.
func (g *ManagerGateway) Run(done <-chan struct{}, ready ...chan<- struct{}) error {
	if g.cfg.ListenAddr != "" {
		conn, err := net.ListenPacket("udp", g.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("usm manager-gateway: front listener: %w", err)
		}
		g.conn = conn
		defer conn.Close()

		agentConn, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("usm manager-gateway: agent socket: %w", err)
		}
		g.agentConn = agentConn
		defer agentConn.Close()
	}
	if g.cfg.TrapListenAddr != "" {
		tconn, err := net.ListenPacket("udp", g.cfg.TrapListenAddr)
		if err != nil {
			return fmt.Errorf("usm manager-gateway: trap listener: %w", err)
		}
		g.trapConn = tconn
		defer tconn.Close()
	}

	for _, r := range ready {
		close(r)
	}

	if g.conn != nil {
		go g.readFront()
		go g.readAgent()
	}
	if g.trapConn != nil {
		go g.readTraps()
	}

	select {
	case <-done:
	case <-g.stop:
	}
	return nil
}

// Stop closes the translator (tests).
func (g *ManagerGateway) Stop() {
	select {
	case <-g.stop:
	default:
		close(g.stop)
	}
}

// readFront reads clear v1/v2c requests from the legacy manager.
func (g *ManagerGateway) readFront() {
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
		g.handleClearRequest(addr, dg)
	}
}

// handleClearRequest parses a clear v1/v2c request from the legacy
// manager, wraps it into an authenticated+encrypted v3 request toward
// the real agent, and registers a pending entry so the response path
// can strip the security back off.
func (g *ManagerGateway) handleClearRequest(addr net.Addr, dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil {
		return
	}
	if info.Version != msg.Version1 && info.Version != msg.Version2c {
		// v3 from the manager side is not this mode's contract; ignore.
		return
	}
	_, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}
	fields, ok := pduCommon(pduTLV)
	if !ok {
		return
	}

	eng, err := g.ensureEngine()
	if err != nil {
		g.log.Warn("usm manager-gateway: agent discovery failed", zap.Error(err))
		return
	}

	scoped := msg.BuildScoped(eng.id, []byte{}, pduTLV)
	out, msgID, err := g.buildV3Request(eng, scoped)
	if err != nil {
		g.log.Warn("usm manager-gateway: v3 wrap failed", zap.Error(err))
		return
	}

	pend := &mgwPending{
		managerAddr: addr,
		ver:         info.Version,
		community:   community,
		clientReqID: fields.ReqID,
		ready:       make(chan struct{}),
	}
	g.pendMu.Lock()
	g.pend[msgID] = pend
	g.pendMu.Unlock()

	agent, aerr := net.ResolveUDPAddr("udp", g.cfg.AgentAddr)
	if aerr != nil {
		g.pendMu.Lock()
		delete(g.pend, msgID)
		g.pendMu.Unlock()
		g.log.Warn("usm manager-gateway: bad agent_addr", zap.Error(aerr))
		return
	}
	if _, err := g.agentConn.WriteTo(out, agent); err != nil {
		g.pendMu.Lock()
		delete(g.pend, msgID)
		g.pendMu.Unlock()
		g.log.Warn("usm manager-gateway: agent delivery failed", zap.Error(err))
		return
	}
	if g.met != nil {
		g.met.ReqForwarded.Inc()
	}

	go func() {
		select {
		case <-g.waitForPend(msgID):
			// handled by readAgent (response relayed already)
		case <-time.After(15 * time.Second):
			g.log.Debug("usm manager-gateway: agent response timed out")
			g.pendMu.Lock()
			if g.pend[msgID] == pend {
				delete(g.pend, msgID)
			}
			g.pendMu.Unlock()
		case <-g.stop:
		}
	}()
}

// waitForPend returns the ready channel of the pending request.
func (g *ManagerGateway) waitForPend(msgID int32) <-chan struct{} {
	g.pendMu.Lock()
	defer g.pendMu.Unlock()
	if p, ok := g.pend[msgID]; ok {
		return p.ready
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// readAgent reads v3 responses from the real agent, verifies/decrypts
// them with keys localized to the agent's engineID from the wire, and
// relays the stripped clear response back to the legacy manager.
func (g *ManagerGateway) readAgent() {
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

// handleAgentResponse verifies a v3 message from the agent, adopts
// engine-state changes (Reports follow the wire), and relays GetResponses
// to the waiting manager.
func (g *ManagerGateway) handleAgentResponse(dg []byte) {
	m2, err := msg.ParseV3(dg)
	if err != nil {
		g.log.Debug("usm manager-gateway: undecodable v3 from agent", zap.Error(err))
		return
	}
	// Reports carry the agent's engine state: adopt them (the agent
	// rebooted → boots went up; the notInTime Report re-syncs this
	// cache so the next request uses fresh engine clocks).
	if len(m2.PDU) > 0 && m2.PDU[0] == msg.PDUReport {
		g.adoptEngine(m2)
		return
	}
	keys, kerr := g.keys.profilesFor(m2.USM.EngineID)
	if kerr != nil {
		g.log.Debug("usm manager-gateway: no keys for engine", zap.Error(kerr))
		return
	}
	_, pdu, err := unwrapV3(keys, m2, dg)
	if err != nil {
		g.log.Debug("usm manager-gateway: response rejected", zap.Error(err))
		return
	}
	fields, fieldsOK := pduCommon(pdu)
	if !fieldsOK || !msg.IsGetResponse(pdu[0]) {
		return
	}

	// match the pending request by the v3 msgID we sent
	g.pendMu.Lock()
	pend, ok := g.pend[m2.Header.MsgID]
	if !ok {
		g.pendMu.Unlock()
		g.log.Debug("usm manager-gateway: response with no pending request", zap.Int32("msgID", m2.Header.MsgID))
		return
	}
	delete(g.pend, m2.Header.MsgID)
	g.pendMu.Unlock()

	// strip back to clear: the manager's original req-id, original
	// community, original version
	resp := msg.BuildPDU(msg.PDUGetResponse, pend.clientReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(pend.ver, pend.community, resp)
	if err != nil {
		return
	}
	pend.resp = out
	close(pend.ready)
	if udp, ok := pend.managerAddr.(*net.UDPAddr); ok {
		if _, err := g.conn.WriteTo(pend.resp, udp); err != nil {
			g.log.Debug("usm manager-gateway: manager delivery failed", zap.Error(err))
		}
	}
}

// adoptEngine adopts a Report from the agent (engine state changes).
func (g *ManagerGateway) adoptEngine(m2 *msg.V3Message) {
	if len(m2.USM.EngineID) == 0 {
		return
	}
	g.engineMu.Lock()
	newer := g.remote == nil ||
		!bytes.Equal(m2.USM.EngineID, g.remote.id) ||
		m2.USM.Boots != g.remote.boots ||
		m2.USM.Time != g.remote.time
	if newer {
		g.remote = &remoteEngine{
			id:           append([]byte{}, m2.USM.EngineID...),
			boots:        m2.USM.Boots,
			time:         m2.USM.Time,
			discoveredAt: time.Now(),
		}
	}
	g.engineMu.Unlock()
	g.log.Info("usm manager-gateway: agent engine state adopted",
		zap.String("engineID", hex.EncodeToString(m2.USM.EngineID)),
		zap.Uint32("boots", m2.USM.Boots),
		zap.Uint32("time", m2.USM.Time))
}

// ensureEngine returns the discovered agent engine, performing RFC 3414
// discovery (a Reportable NoAuthNoPriv empty GET toward the agent) when
// absent or stale (60s TTL).
func (g *ManagerGateway) ensureEngine() (*remoteEngine, error) {
	g.engineMu.Lock()
	if g.remote != nil && time.Since(g.remote.discoveredAt) < 60*time.Second {
		eng := g.remote
		g.engineMu.Unlock()
		return eng, nil
	}
	g.engineMu.Unlock()

	pdu := msg.BuildPDU(msg.PDUGetRequest, int32(g.reqID.Add(1)), 0, 0, []byte{0})
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(g.msgID.Add(1)),
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable, // NoAuthNoPriv + reportable
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		return nil, err
	}

	agent, err := net.ResolveUDPAddr("udp", g.cfg.AgentAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.WriteTo(out, agent); err != nil {
		return nil, err
	}

	// one discovery probe per call: the answer is a Report from the
	// agent's authoritative engine
	buf := make([]byte, 65536)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, errors.New("usm manager-gateway: discovery timed out")
		}
		dg := append([]byte{}, buf[:n]...)
		m2, err := msg.ParseV3(dg)
		if err != nil || len(m2.USM.EngineID) == 0 {
			continue // stray datagram
		}
		g.adoptEngine(m2)
		g.engineMu.Lock()
		eng := g.remote
		g.engineMu.Unlock()
		if eng != nil {
			return eng, nil
		}
	}
}

// buildV3Request builds a signed+encrypted v3 request toward the agent
// using the first configured user (the agent-side credentials), with
// keys localized to the agent's engineID. Returns the marshalled message
// and the v3 msgID used (for response matching).
func (g *ManagerGateway) buildV3Request(eng *remoteEngine, scoped []byte) ([]byte, int32, error) {
	keys, err := g.keys.profilesFor(eng.id)
	if err != nil {
		return nil, 0, err
	}
	users := profilesFromConfig(g.sec)
	if len(users) == 0 {
		return nil, 0, errors.New("usm manager-gateway: no users configured")
	}
	u := users[0]
	c, ok := keys.Lookup(u.Name)
	if !ok {
		return nil, 0, fmt.Errorf("usm manager-gateway: user %s not found", u.Name)
	}

	// capture the msgID BEFORE building the header: returning the
	// counter's latest value instead would hand back another request's
	// msgID under concurrency and mis-correlate the response.
	mid := int32(g.msgID.Add(1))
	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable)
	boots := eng.boots
	etime := eng.time
	privParams := g.salt.NextAES()
	authParams := make([]byte, c.p.AuthProtocol.MacLength())

	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      mid,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   eng.id,
		Boots:      boots,
		Time:       etime,
		UserName:   u.Name,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, privParams, plain)
	})
	if err != nil {
		return nil, 0, err
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		return nil, 0, err
	}
	return out, mid, nil
}

// readTraps reads v3 notifications from the v3 agent at the trap
// listener, verifies/unwraps them, and relays them as clear v1/v2c
// toward the legacy manager's trap receiver (trap_sink_addr). Informs
// are answered directly by this proxy (the confirmation terminates
// here) and their payload relayed as a clear trap.
func (g *ManagerGateway) readTraps() {
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
		g.handleAgentTrap(dg)
	}
}

// handleAgentTrap verifies a v3 notification from the agent and relays
// it as a clear v1/v2c notification toward the manager's trap receiver.
func (g *ManagerGateway) handleAgentTrap(dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil || info.Version != msg.Version3 {
		return
	}
	m2, err := msg.ParseV3(dg)
	if err != nil {
		g.log.Debug("usm manager-gateway: undecodable trap", zap.Error(err))
		return
	}
	keys, kerr := g.keys.profilesFor(m2.USM.EngineID)
	if kerr != nil {
		g.log.Debug("usm manager-gateway: no keys for trap engine", zap.Error(kerr))
		return
	}
	_, pdu, err := unwrapV3(keys, m2, dg)
	if err != nil {
		g.log.Warn("usm manager-gateway: trap rejected (bad digest/stale time)", zap.Error(err))
		return
	}

	pduType := pdu[0]
	fields, ok := pduCommon(pdu)
	if !ok {
		return
	}
	varbs := fields.Varbinds
	if msg.IsInform(pduType) {
		// answer the agent directly (the confirmation terminates here):
		// a v3 GetResponse echoing the inform's msgID/req-id/engine.
		resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, fields.Varbinds)
		scoped := msg.BuildScoped(m2.USM.EngineID, []byte{}, resp)
		out, _, oerr := g.buildV3Request(&remoteEngine{
			id:           m2.USM.EngineID,
			boots:        m2.USM.Boots,
			time:         m2.USM.Time,
			discoveredAt: time.Now(),
		}, scoped)
		if oerr != nil {
			g.log.Warn("usm manager-gateway: inform response build failed", zap.Error(oerr))
		} else if agent, aerr := net.ResolveUDPAddr("udp", g.cfg.AgentAddr); aerr == nil {
			// reply to the sender: best-effort, from the trap listener
			// socket toward the agent.
			if _, werr := g.trapConn.WriteTo(out, agent); werr != nil {
				g.log.Debug("usm manager-gateway: inform response failed", zap.Error(werr))
			}
		}
		// relay the payload as a plain v2 trap
		pduType = msg.PDUSNMPv2Trap
	}

	if g.cfg.TrapSinkAddr == "" {
		return
	}
	clear := msg.BuildPDU(pduType, 0, 0, 0, varbs)
	comm := g.cfg.TrapSinkCommunity
	if comm == "" {
		comm = "public"
	}
	out, err := msg.BuildV1V2c(msg.Version2c, []byte(comm), clear)
	if err != nil {
		return
	}
	sink, serr := net.ResolveUDPAddr("udp", g.cfg.TrapSinkAddr)
	if serr != nil {
		return
	}
	if _, err := g.trapConn.WriteTo(out, sink); err != nil {
		g.log.Debug("usm manager-gateway: trap sink delivery failed", zap.Error(err))
	}
}
