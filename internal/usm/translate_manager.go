// translate_manager.go: manager-side USM translate mode. This proxy
// listens for clear v1/v2c SNMP from managers, wraps each PDU into an
// SNMPv3 authPriv message signed+encrypted for the agent-side engine
// (after RFC 3414 discovery), and unwraps v3 responses back into v1/v2c.
// It also originates v3 notifications for local device traps and delivers
// tunnel notifications to the local trap sink.
package usm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/cache"
	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// remoteEngine is the agent-side engine as discovered via RFC 3414.
type remoteEngine struct {
	id           []byte
	boots        uint32
	time         uint32
	discoveredAt time.Time
}

// mgrPending is one in-flight tunneled request (by tunnel corrID).
type mgrPending struct {
	addr        net.Addr // manager that sent the clear request
	ver         int      // clear version to rebuild for the response
	community   string
	clientReqID int32 // req-id from the clear request (echoed back)
	isDiscovery bool
	ready       chan struct{}
	resp        []byte
}

// ManagerTranslator is the manager-side USM translation engine.
type ManagerTranslator struct {
	translatorBase

	cfg   config.ManagerRole
	sec   config.Security
	prof  *Profiles // users compiled against the remote engine (per engine: keys)
	clock *cache.EngineClock
	sess  FrameSink
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	engineMu sync.Mutex
	remote   *remoteEngine
	msgID    atomic.Uint32
	reqID    atomic.Uint32
	corrID   atomic.Uint32

	pendMu sync.Mutex
	pend   map[uint16]*mgrPending

	// clear-leg listeners
	conn     net.PacketConn // clear request listener
	trapConn net.PacketConn // clear trap listener (optional)
	sink     net.Addr       // local trap sink (optional, lazily dialed)

	stop chan struct{}
}

// NewManagerTranslator builds the manager-side translator.
func NewManagerTranslator(cfg config.ManagerRole, sec config.Security, clock *cache.EngineClock, sess FrameSink, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*ManagerTranslator, error) {
	// primary profile set is compiled lazily per remote engine (keys are
	// localized per engine); keep a base compiled set for salt selection.
	return &ManagerTranslator{
		translatorBase: translatorBase{
			keys:   newKeyCache(profilesFromConfig(sec)),
			replay: newReplayCache(),
		},
		cfg:   cfg,
		sec:   sec,
		clock: clock,
		sess:  sess,
		log:   log,
		met:   met,
		filtr: notifyfilter.From(filt...),
		pend:  make(map[uint16]*mgrPending),
		stop:  make(chan struct{}),
	}, nil
}

// Run starts the translator: binds the clear listener(s), subscribes to
// tunnel RESP/NOTIF frames, and serves until done is closed.
func (m *ManagerTranslator) Run(done <-chan struct{}) error {
	conn, err := net.ListenPacket("udp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("usm manager: clear listener: %w", err)
	}
	m.conn = conn
	defer conn.Close()

	if m.cfg.TrapListenAddr != "" {
		tconn, terr := net.ListenPacket("udp", m.cfg.TrapListenAddr)
		if terr != nil {
			return fmt.Errorf("usm manager: trap listener: %w", terr)
		}
		m.trapConn = tconn
		defer tconn.Close()
	}

	if m.cfg.TrapSinkAddr != "" {
		if saddr, serr := net.ResolveUDPAddr("udp", m.cfg.TrapSinkAddr); serr == nil {
			m.sink = saddr
		} else {
			m.log.Warn("usm manager: cannot resolve trap sink", zap.String("sink", m.cfg.TrapSinkAddr), zap.Error(serr))
		}
	}

	respCh, cancelResp := m.sess.Subscribe(msgTypeRESP)
	defer cancelResp()
	notifCh, cancelNotif := m.sess.Subscribe(msgTypeNOTIF)
	defer cancelNotif()

	go m.readClear()
	if m.trapConn != nil {
		go m.readTraps()
	}

	for {
		select {
		case <-done:
			close(m.stop)
			return nil
		case f, ok := <-respCh:
			if !ok {
				return nil
			}
			m.handleTunnelResponse(f)
		case f, ok := <-notifCh:
			if !ok {
				return nil
			}
			m.handleTunnelNotif(f)
		}
	}
}

// readClear reads clear requests from managers.
func (m *ManagerTranslator) readClear() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		m.handleClearRequest(addr, dg)
	}
}

// handleClearRequest wraps one clear v1/v2c request into a v3 authPriv
// message and ships it over the tunnel.
func (m *ManagerTranslator) handleClearRequest(addr net.Addr, dg []byte) {
	ver, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		m.log.Debug("usm manager: undecodable clear request", zap.Error(err))
		return
	}
	info, err := msg.Peek(dg)
	if err != nil {
		return
	}
	fields, fieldsOK := pduCommon(pduTLV)
	if !fieldsOK {
		m.log.Debug("usm manager: undecodable PDU in clear request")
		return
	}

	// discovery (synchronous, on first use / refresh / Report-triggered)
	eng, err := m.ensureEngine()
	if err != nil {
		m.log.Warn("usm manager: discovery failed", zap.Error(err))
		return
	}

	corrID := uint16(m.corrID.Add(1))
	pend := &mgrPending{
		addr:        addr,
		ver:         ver,
		community:   string(community),
		clientReqID: info.RequestID,
		ready:       make(chan struct{}),
	}
	m.pendMu.Lock()
	m.pend[corrID] = pend
	m.pendMu.Unlock()

	// v3 request: own req-id (matched back on response), Auth|Priv|Reportable
	newReqID := int32(m.reqID.Add(1))
	pdu := msg.BuildPDU(pduTLV[0], newReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	scoped := msg.BuildScoped(eng.id, []byte{}, pdu)
	out, err := m.buildV3Request(eng, scoped, true)
	if err != nil {
		m.log.Debug("usm manager: request build failed", zap.Error(err))
		m.pendMu.Lock()
		delete(m.pend, corrID)
		m.pendMu.Unlock()
		return
	}

	if err := m.sess.Send(context.Background(), msgTypeREQ, 0, corrID, out); err != nil {
		m.log.Debug("usm manager: tunnel send failed", zap.Error(err))
		m.pendMu.Lock()
		delete(m.pend, corrID)
		m.pendMu.Unlock()
		return
	}
	if m.met != nil {
		m.met.ReqForwarded.Inc()
	}

	// response timeout
	go func() {
		select {
		case <-time.After(15 * time.Second):
			m.pendMu.Lock()
			if m.pend[corrID] == pend {
				delete(m.pend, corrID)
			}
			m.pendMu.Unlock()
		case <-pend.ready:
		}
	}()
}

// handleTunnelResponse unwraps a v3 response/report from the tunnel.
func (m *ManagerTranslator) handleTunnelResponse(f *tunnel.Frame) {
	m2, err := msg.ParseV3(f.Payload)
	if err != nil {
		m.log.Debug("usm manager: undecodable v3 from tunnel", zap.Error(err))
		return
	}

	// reports (unauthenticated, from the authoritative engine)
	if len(m2.PDU) > 0 && m2.PDU[0] == msg.PDUReport {
		m.handleReport(m2)
		return
	}

	// responses: authenticate + decrypt against the remote engine's keys
	keys, kerr := m.keys.profilesFor(m2.USM.EngineID)
	if kerr != nil {
		m.log.Debug("usm manager: no keys for engine", zap.Error(kerr))
		return
	}
	c, pdu, err := unwrapV3(keys, m2, f.Payload)
	if err != nil {
		m.log.Debug("usm manager: response rejected", zap.Error(err))
		return
	}
	_ = c
	fields, fieldsOK := pduCommon(pdu)
	if !fieldsOK {
		m.log.Debug("usm manager: undecodable PDU in tunnel response")
		return
	}

	// match pending by tunnel corrID
	m.pendMu.Lock()
	pend, ok := m.pend[f.CorrID]
	if !ok {
		m.pendMu.Unlock()
		m.log.Debug("usm manager: response with no pending request", zap.Uint16("corrID", f.CorrID))
		return
	}
	delete(m.pend, f.CorrID)
	m.pendMu.Unlock()

	// rebuild the clear response with the manager's req-id
	resp := msg.BuildPDU(pdu[0], pend.clientReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(pend.ver, []byte(pend.community), resp)
	if err != nil {
		return
	}
	pend.resp = out
	close(pend.ready)

	if udp, ok2 := pend.addr.(*net.UDPAddr); ok2 {
		if _, err := m.conn.WriteTo(out, udp); err != nil {
			m.log.Debug("usm manager: response delivery failed", zap.Error(err))
		}
	}
}

// handleReport processes a Report PDU from the authoritative engine: the
// engineID/boots/time in its USM parameters update the discovery state.
func (m *ManagerTranslator) handleReport(m2 *msg.V3Message) {
	if len(m2.USM.EngineID) == 0 {
		return
	}
	m.engineMu.Lock()
	newer := m.remote == nil ||
		m2.USM.Boots > m.remote.boots ||
		(m2.USM.Boots == m.remote.boots && m2.USM.Time >= m.remote.time)
	if newer {
		m.remote = &remoteEngine{
			id:           append([]byte{}, m2.USM.EngineID...),
			boots:        m2.USM.Boots,
			time:         m2.USM.Time,
			discoveredAt: time.Now(),
		}
	}
	m.engineMu.Unlock()
	m.log.Info("usm manager: engine discovered",
		zap.String("engineID", hex.EncodeToString(m2.USM.EngineID)),
		zap.Uint32("boots", m2.USM.Boots),
		zap.Uint32("time", m2.USM.Time))

	// wake pending discovery requests so they re-check engine state
	m.pendMu.Lock()
	for _, p := range m.pend {
		if p.isDiscovery {
			select {
			case <-p.ready:
			default:
			}
			close(p.ready)
		}
	}
	m.pendMu.Unlock()
}

// ensureEngine returns the discovered remote engine, performing discovery
// (a Reportable NoAuthNoPriv empty GET) when absent or stale.
func (m *ManagerTranslator) ensureEngine() (*remoteEngine, error) {
	m.engineMu.Lock()
	if m.remote != nil && time.Since(m.remote.discoveredAt) < 60*time.Second {
		eng := m.remote
		m.engineMu.Unlock()
		return eng, nil
	}
	m.engineMu.Unlock()

	// discovery: empty GetRequest, Reportable|NoAuthNoPriv, empty user
	pdu := msg.BuildPDU(msg.PDUGetRequest, int32(m.reqID.Add(1)), 0, 0, []byte{0})
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(m.msgID.Add(1)),
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable, // NoAuthNoPriv + reportable
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		return nil, err
	}

	corrID := uint16(m.corrID.Add(1))
	pend := &mgrPending{
		addr:        nil,
		isDiscovery: true,
		ready:       make(chan struct{}),
	}
	m.pendMu.Lock()
	m.pend[corrID] = pend
	m.pendMu.Unlock()

	if err := m.sess.Send(context.Background(), msgTypeREQ, 0, corrID, out); err != nil {
		m.pendMu.Lock()
		delete(m.pend, corrID)
		m.pendMu.Unlock()
		return nil, err
	}

	select {
	case <-pend.ready:
	case <-time.After(5 * time.Second):
	}
	m.pendMu.Lock()
	delete(m.pend, corrID)
	m.pendMu.Unlock()

	m.engineMu.Lock()
	defer m.engineMu.Unlock()
	if m.remote == nil {
		return nil, errors.New("usm manager: discovery timed out")
	}
	return m.remote, nil
}

// buildV3Request builds a signed+encrypted v3 request for the remote
// engine using the primary user.
func (m *ManagerTranslator) buildV3Request(eng *remoteEngine, scoped []byte, authPriv bool) ([]byte, error) {
	users := profilesFromConfig(m.sec)
	if len(users) == 0 {
		return nil, errors.New("usm manager: no users configured")
	}
	u := users[0]
	keys, err := m.keys.profilesFor(eng.id)
	if err != nil {
		return nil, err
	}
	c, ok := keys.Lookup(u.Name)
	if !ok {
		return nil, fmt.Errorf("usm manager: user %s not found", u.Name)
	}

	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable)
	boots := eng.boots
	etime := eng.time
	privParams := m.salt.NextAES()

	var authParams []byte
	if flags&msg.MsgFlagAuth != 0 {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}

	scopedOut := scoped
	var encrypt func([]byte) ([]byte, error)
	if flags&msg.MsgFlagPriv != 0 {
		encrypt = func(plain []byte) ([]byte, error) {
			return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, privParams, plain)
		}
	}
	_ = scopedOut

	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      int32(m.msgID.Add(1)),
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
	}, scoped, encrypt)
	if err != nil {
		return nil, err
	}
	if flags&msg.MsgFlagAuth != 0 {
		if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readTraps reads clear notifications from local devices.
func (m *ManagerTranslator) readTraps() {
	buf := make([]byte, 65536)
	for {
		n, _, err := m.trapConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dg := append([]byte{}, buf[:n]...)
		m.handleClearTrap(dg)
	}
}

// handleClearTrap wraps a local device notification into a v3 authPriv
// message and ships it over the tunnel as a NOTIF frame.
func (m *ManagerTranslator) handleClearTrap(dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil {
		return
	}
	if m.filtr != nil && (msg.IsTrap(info.PDUType) || msg.IsInform(info.PDUType)) {
		oid, ok := msg.TrapOID(dg)
		if !ok || !m.filtr.Allowed(oid) {
			if m.met != nil {
				m.met.NotifsFiltered.Inc()
			}
			m.log.Debug("usm manager: notification filtered", zap.String("trap_oid", oid))
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

	eng, err := m.ensureEngine()
	if err != nil {
		m.log.Warn("usm manager: trap dropped (no engine)", zap.Error(err))
		return
	}

	scoped := msg.BuildScoped(eng.id, []byte{}, pdu)
	out, err := m.buildV3Request(eng, scoped, true)
	if err != nil {
		m.log.Warn("usm manager: trap build failed", zap.Error(err))
		return
	}
	flags := byte(0)
	if info.PDUType == msg.PDUInformRequest {
		flags = tunnel.FlagInform
	}
	if err := m.sess.Send(context.Background(), msgTypeNOTIF, flags, 0, out); err != nil {
		m.log.Warn("usm manager: trap tunnel send failed", zap.Error(err))
		return
	}
	if m.met != nil {
		m.met.NotifsRelayed.Inc()
	}
}

// handleTunnelNotif validates an inbound v3 trap/inform (originated by the
// agent side for its local devices) and delivers it to the trap sink.
func (m *ManagerTranslator) handleTunnelNotif(f *tunnel.Frame) {
	m2, err := msg.ParseV3(f.Payload)
	if err != nil {
		m.log.Debug("usm manager: undecodable v3 notif", zap.Error(err))
		return
	}
	c, plainPDU, err := m.receiveNotif(f.Payload, m2)
	if err != nil {
		m.log.Debug("usm manager: notif rejected", zap.Error(err))
		return
	}
	_ = c

	if m.sink != nil {
		dg, berr := msg.BuildV1V2c(msg.Version2c, []byte(m.trapCommunity()), plainPDU)
		if berr == nil {
			if werr := m.sinkWrite(dg); werr != nil {
				m.log.Warn("usm manager: trap sink delivery failed", zap.Error(werr))
			} else if m.met != nil {
				m.met.NotifsRelayed.Inc()
			}
		}
	}

	// inform: respond with a v3 GetResponse echoing the inform's USM params
	if len(m2.PDU) > 0 && m2.PDU[0] == msg.PDUInformRequest {
		m.sendInformResponse(f, m2, plainPDU)
	}
}

// sendInformResponse answers an inbound inform.
func (m *ManagerTranslator) sendInformResponse(f *tunnel.Frame, m2 *msg.V3Message, pdu []byte) {
	keys, err := m.keys.profilesFor(m2.USM.EngineID)
	if err != nil {
		return
	}
	c, ok := keys.Lookup(m2.USM.UserName)
	if !ok {
		return
	}
	ifFields, ifOK := pduCommon(pdu)
	var resp []byte
	if ifOK {
		resp = msg.BuildPDU(msg.PDUGetResponse, ifFields.ReqID, 0, 0, ifFields.Varbinds)
	} else {
		resp = msg.BuildPDU(msg.PDUGetResponse, 0, 0, 0, []byte{0})
	}
	var authParams []byte
	var privParams []byte
	if m2.Header.MsgFlags&msg.MsgFlagAuth != 0 {
		authParams = make([]byte, c.p.AuthProtocol.MacLength())
	}
	if m2.Header.MsgFlags&msg.MsgFlagPriv != 0 {
		if c.p.PrivProtocol == PrivDES {
			privParams = m.salt.NextDES(m2.USM.Boots)
		} else {
			privParams = m.salt.NextAES()
		}
	}
	scoped := msg.BuildScoped(m2.ContextEngineID, []byte{}, resp)
	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, m2.USM.Boots, m2.USM.Time, privParams, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      m2.Header.MsgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   m2.Header.MsgFlags | msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   m2.USM.EngineID,
		Boots:      m2.USM.Boots,
		Time:       m2.USM.Time,
		UserName:   m2.USM.UserName,
		AuthParams: authParams,
		PrivParams: privParams,
	}, scoped, encrypt)
	if err != nil {
		return
	}
	if m2.Header.MsgFlags&msg.MsgFlagAuth != 0 {
		_ = signV3(out, c.p.AuthProtocol, c.authKey)
	}
	_ = m.sess.Send(context.Background(), msgTypeRESP, tunnel.FlagInform, f.CorrID, out)
}

// sinkWrite sends a datagram to the configured trap sink.
func (m *ManagerTranslator) sinkWrite(dg []byte) error {
	udp, ok := m.sink.(*net.UDPAddr)
	if !ok {
		return errors.New("usm manager: no sink")
	}
	conn, err := net.DialUDP("udp", nil, udp)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(dg)
	return err
}

// trapCommunity is the v1/v2c community used in notifications delivered to
// the local trap sink.
func (m *ManagerTranslator) trapCommunity() string {
	if m.sec.TrapCommunity != "" {
		return m.sec.TrapCommunity
	}
	return "public"
}

// ProfilesFromSecurity converts config users into Profiles.
func ProfilesFromSecurity(sec config.Security) []Profile {
	return profilesFromConfig(sec)
}

// profilesFromConfig converts config users into Profiles.
func profilesFromConfig(sec config.Security) []Profile {
	users := make([]Profile, 0, len(sec.Users))
	for _, u := range sec.Users {
		ap, err := ParseAuthProtocol(u.AuthProtocol)
		if err != nil {
			continue
		}
		pp, err := ParsePrivProtocol(u.PrivProtocol)
		if err != nil {
			continue
		}
		users = append(users, Profile{
			Name:           u.Name,
			AuthProtocol:   ap,
			AuthPassphrase: u.AuthPassphrase,
			PrivProtocol:   pp,
			PrivPassphrase: u.PrivPassphrase,
			Community:      u.Community,
		})
	}
	return users
}
