// manager_gateway.go: single-box USM-manager role — the mirror of the
// usm-gateway. This proxy protects the MANAGER leg: clear v1/v2c
// traps/informs from devices arrive on a plain-UDP trap listener, and the
// proxy wraps each into an authenticated+encrypted SNMPv3 USM notification
// (this proxy is the authoritative engine, first configured user) toward
// the manager's trap receiver (trap_sink_addr). Informs are confirmed: the
// manager's v3 GetResponse is verified/decrypted against the sink's engine
// keys and the clear response is rebuilt back to the device. No tunnel, no
// second proxy.
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

// ManagerGateway secures the manager leg of a SNMP deployment: it accepts
// clear v1/v2c notifications from devices, wraps them into v3 USM
// authPriv notifications (own engine, first user) toward the manager's
// trap receiver, and relays inform responses back to the device.
type ManagerGateway struct {
	translatorBase

	cfg   config.GatewayRole
	users []Profile
	clock *cache.EngineClock
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	msgID atomic.Uint32

	// pending informs keyed on the v3 msgID sent to the sink
	pendMu sync.Mutex
	pend   map[int32]*mgPend

	trapConn net.PacketConn
	stop     chan struct{}
}

// mgPend is one in-flight forwarded inform.
type mgPend struct {
	addr        net.Addr // device that sent the clear inform
	community   []byte   // original clear community (echoed back)
	ver         int      // original SNMP version (1 or 2c)
	clientReqID int32    // req-id from the clear inform (echoed back)
	resp        []byte   // rebuilt clear response (stashed by readManager)
	ready       chan struct{}
}

// NewManagerGateway builds the single-box manager-securing gateway.
func NewManagerGateway(cfg config.GatewayRole, users []Profile, clock *cache.EngineClock, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*ManagerGateway, error) {
	if len(users) == 0 {
		return nil, errors.New("usm manager gateway: at least one user is required")
	}
	if _, err := NewProfiles(users, clock.EngineID()); err != nil {
		return nil, err
	}
	return &ManagerGateway{
		translatorBase: translatorBase{
			keys:   newKeyCache(users),
			replay: newReplayCache(),
		},
		cfg:   cfg,
		users: users,
		clock: clock,
		log:   log,
		met:   met,
		filtr: notifyfilter.From(filt...),
		pend:  make(map[int32]*mgPend),
		stop:  make(chan struct{}),
	}, nil
}

// Run binds the clear trap listener and serves until done is closed. When
// supplied, ready is closed after the listener has been bound.
func (g *ManagerGateway) Run(done <-chan struct{}, ready ...chan<- struct{}) error {
	conn, err := net.ListenPacket("udp", g.cfg.TrapListenAddr)
	if err != nil {
		return fmt.Errorf("usm manager gateway: trap listener: %w", err)
	}
	g.trapConn = conn
	defer conn.Close()

	go g.readLoop()
	if len(ready) > 0 && ready[0] != nil {
		close(ready[0])
	}

	<-done
	close(g.stop)
	return nil
}

// readLoop reads datagrams from the trap listener socket. Both directions
// share one socket: devices send clear v1/v2c notifications in, and the
// manager's v3 responses to our wrapped informs come back to the same
// address. A single reader dispatches by type (two competing ReadFrom
// loops would randomly steal each other's datagrams).
func (g *ManagerGateway) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := g.trapConn.ReadFrom(buf)
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
		// v3 from the manager (inform responses) vs clear v1/v2c from
		// devices: Peek distinguishes them cheaply.
		if info, perr := msg.Peek(dg); perr == nil && info.Version == msg.Version3 {
			g.handleManagerResponse(dg)
			continue
		}
		g.handleClearTrap(addr, dg)
	}
}

// handleClearTrap wraps one clear v1/v2c notification into an
// authenticated+encrypted v3 USM notification and sends it to the
// manager's trap receiver. Informs are tracked so the manager's response
// can be relayed back to the device.
func (g *ManagerGateway) handleClearTrap(addr net.Addr, dg []byte) {
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
			g.log.Debug("usm manager gateway: notification filtered", zap.String("trap_oid", oid))
			return
		}
	}
	_, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}

	var pdu []byte
	var clientReqID int32
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
	case msg.IsInform(info.PDUType):
		// inform: fresh req-id so we can match the manager's response;
		// keep the original varbinds (BER TLV content after the PDU header)
		fields, iok := pduCommon(pduTLV)
		if !iok {
			return
		}
		// remember the DEVICE's req-id: the clear response must echo it
		// back (the fresh req-id below is only for response matching).
		clientReqID = fields.ReqID
		pdu = msg.BuildPDU(msg.PDUInformRequest, int32(g.msgID.Add(1)), 0, 0, fields.Varbinds)
	default:
		pdu = pduTLV
	}

	out, msgID, err := g.buildNotif(pdu, msg.IsInform(info.PDUType))
	if err != nil {
		g.log.Warn("usm manager gateway: notification wrap failed", zap.Error(err))
		return
	}
	if g.cfg.TrapSinkAddr == "" {
		g.log.Debug("usm manager gateway: notification dropped (no trap_sink_addr configured)")
		return
	}
	var pendRef *mgPend
	if msg.IsInform(info.PDUType) {
		pend := &mgPend{
			addr:        addr,
			community:   community,
			ver:         info.Version,
			clientReqID: clientReqID,
			ready:       make(chan struct{}),
		}
		pendRef = pend
		g.pendMu.Lock()
		g.pend[msgID] = pend
		g.pendMu.Unlock()
	}
	// send the wrapped notification FROM the trap listener socket: the
	// manager's inform response comes back to the packet's source address,
	// which must be our trap listener (the device's clear response is
	// rebuilt there).
	sink, serr := net.ResolveUDPAddr("udp", g.cfg.TrapSinkAddr)
	if serr != nil {
		g.log.Warn("usm manager gateway: bad trap_sink_addr", zap.Error(serr))
		return
	}
	if _, err := g.trapConn.WriteTo(out, sink); err != nil {
		g.log.Warn("usm manager gateway: trap sink delivery failed", zap.Error(err))
		return
	}
	if g.met != nil {
		g.met.NotifsRelayed.Inc()
	}
	if msg.IsInform(info.PDUType) {
		// The inform wait must NOT block the read loop: readLoop calls
		// this handler synchronously, so a blocking 15s wait here stalls
		// every subsequent datagram (including the manager's response
		// itself). Wait in a goroutine and rebuild the clear response
		// from there.
		go func() {
			select {
			case <-g.waitForInform(msgID):
				// ready closed by handleManagerResponse, which relayed
				// the response already (with the pend pointer).
			case <-time.After(15 * time.Second):
				g.log.Debug("usm manager gateway: inform response timed out")
				g.pendMu.Lock()
				if g.pend[msgID] == pendRef {
					delete(g.pend, msgID)
				}
				g.pendMu.Unlock()
				return
			case <-g.stop:
				return
			}
		}()
	}
}

// waitForInform returns the ready channel of the pending inform.
func (g *ManagerGateway) waitForInform(msgID int32) <-chan struct{} {
	g.pendMu.Lock()
	defer g.pendMu.Unlock()
	if p, ok := g.pend[msgID]; ok {
		return p.ready
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// buildNotif builds a signed+encrypted v3 USM notification for the
// manager's trap receiver using the first configured user and this
// gateway's own engine state (no discovery: we are the engine). Returns
// the marshalled message and the v3 msgID used (for inform matching).
func (g *ManagerGateway) buildNotif(pdu []byte, reportable bool) ([]byte, int32, error) {
	if len(g.users) == 0 {
		return nil, 0, errors.New("usm manager gateway: no users configured")
	}
	c, ok := g.profLookup(g.users[0].Name)
	if !ok {
		return nil, 0, fmt.Errorf("usm manager gateway: user %s not found", g.users[0].Name)
	}

	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv)
	if reportable {
		flags |= msg.MsgFlagReportable
	}
	msgID := int32(g.msgID.Add(1))
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
		MsgID:      msgID,
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
		return nil, 0, err
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		return nil, 0, err
	}
	return out, msgID, nil
}

// profLookup compiles the configured users against our own engine and
// looks a user up (buildNotif helper; our own engine keys are cached).
func (g *ManagerGateway) profLookup(name string) (*compiled, bool) {
	profs, err := g.keys.profilesFor(g.clock.EngineID())
	if err != nil {
		return nil, false
	}
	return profs.Lookup(name)
}

// relayInformResponse sends the rebuilt clear response (stashed on the
// pend) back to the device. Takes the pend pointer — the pend is already
// deleted from the map when this runs, so a msgID re-lookup would fail.
func (g *ManagerGateway) relayInformResponse(pend *mgPend) {
	if pend == nil || pend.resp == nil {
		return
	}
	if udp, ok := pend.addr.(*net.UDPAddr); ok {
		if _, err := g.trapConn.WriteTo(pend.resp, udp); err != nil {
			g.log.Debug("usm manager gateway: inform response delivery failed", zap.Error(err))
		}
	}
}

// handleManagerResponse verifies/decrypts a v3 message from the manager's
// trap receiver and, for inform responses, matches the pending inform,
// stashes the rebuilt clear response PDU, and relays it to the device.

func (g *ManagerGateway) handleManagerResponse(dg []byte) {
	m2, err := msg.ParseV3(dg)
	if err != nil {
		g.log.Debug("usm manager gateway: undecodable v3 from manager sink", zap.Error(err))
		return
	}
	// the response is signed/encrypted by the sink's engine: use keys
	// localized for the engineID on the wire (same pattern as inbound
	// notifications).
	keys, kerr := g.keys.profilesFor(m2.USM.EngineID)
	if kerr != nil {
		g.log.Debug("usm manager gateway: no keys for engine", zap.Error(kerr))
		return
	}
	c, pdu, err := unwrapV3(keys, m2, dg)
	if err != nil {
		g.log.Debug("usm manager gateway: response rejected", zap.Error(err))
		return
	}
	_ = c
	fields, fieldsOK := pduCommon(pdu)
	if !fieldsOK || !msg.IsGetResponse(pdu[0]) {
		return
	}

	// match the pending inform by the v3 msgID we sent (the manager
	// echoes msgID in responses)
	g.pendMu.Lock()
	pend, ok := g.pend[m2.Header.MsgID]
	if !ok {
		g.pendMu.Unlock()
		g.log.Debug("usm manager gateway: response with no pending inform", zap.Int32("msgID", m2.Header.MsgID))
		return
	}
	delete(g.pend, m2.Header.MsgID)
	g.pendMu.Unlock()

	resp := msg.BuildPDU(msg.PDUGetResponse, pend.clientReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(pend.ver, pend.community, resp)
	if err != nil {
		return
	}
	pend.resp = out
	close(pend.ready)
	// relay directly with the pend pointer: the wait goroutine cannot do
	// the lookup — the pend was already deleted from the map above, so a
	// msgID-based re-lookup would dead-end and the device would never see
	// its response.
	g.relayInformResponse(pend)
}
