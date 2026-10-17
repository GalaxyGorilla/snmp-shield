// Package tsm implements TSM mode (RFC 5591): the tunnel's (D)TLS
// handshake IS the SNMP authentication. The peer certificate chain maps
// to a securityName (the leaf CN); messages cross the tunnel as SNMPv3
// with securityModel=4 (TSM) and an EMPTY securityParameters field per
// RFC 5591, carrying the clear-leg PDU inside the scopedPDU. No USM
// crypto is applied on the tunnel leg: confidentiality and integrity come
// from the (D)TLS session itself.
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

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"go.uber.org/zap"
)

// Errors returned by the TSM path.
var (
	ErrNoCerts      = errors.New("tsm: tunnel provides no peer certificate")
	ErrUnknownPeer  = errors.New("tsm: peer identity not allowed")
	ErrBadScopedPDU = errors.New("tsm: malformed scopedPDU")
)

// FrameSink is the subset of the tunnel Session used by the translators
// (same shape as the USM layer).
type FrameSink interface {
	Send(ctx context.Context, typ, flags uint8, corrID uint16, payload []byte) error
	Subscribe(ftype uint8) (<-chan *tunnel.Frame, func())
}

const (
	msgTypeREQ   = 1
	msgTypeRESP  = 2
	msgTypeNOTIF = 3
)

const reqTimeout = 15 * time.Second

// securityNameFromCerts derives the securityName from the peer leaf
// certificate: the CommonName, falling back to the first DNS/email SAN.
func securityNameFromCerts(certs []*x509.Certificate) (string, error) {
	if len(certs) == 0 {
		return "", ErrNoCerts
	}
	leaf := certs[0]
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName, nil
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0], nil
	}
	if len(leaf.EmailAddresses) > 0 {
		return leaf.EmailAddresses[0], nil
	}
	return "", fmt.Errorf("%w: certificate has no CN or SAN", ErrNoCerts)
}

// wrapTSM builds a v3 TSM message around a clear PDU TLV. The scopedPDU
// carries the caller's context engine ID and the PDU verbatim; secParams
// carry secName (empty per RFC 5591 for our own two-proxy messages;
// net-snmp TSM clients validate that responses echo their securityName).
// msgID/reqID come from the caller's counters; flags are echoed verbatim
// (net-snmp also validates that responses carry the request's security
// level — auth/priv bits — even though TSM secParams stay empty).
func wrapTSM(msgID int32, reqID int32, pduType uint8, pduBody []byte, ctxEngineID []byte, flags byte, secName string) ([]byte, error) {
	pdu := msg.BuildPDU(pduType, reqID, 0, 0, pduBody)
	scoped := msg.BuildScoped(ctxEngineID, []byte{}, pdu)
	return msg.BuildV3(msg.V3Header{
		MsgID:      msgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{UserName: secName}, scoped, nil)
}

// unwrapTSM extracts the clear PDU TLV from a v3 TSM message.
func unwrapTSM(m *msg.V3Message) (pdu []byte, err error) {
	if m.Header.SecModel != msg.SecurityModelTSM {
		return nil, fmt.Errorf("tsm: not a TSM message (secModel %d)", m.Header.SecModel)
	}
	if m.IsEncrypted() {
		return nil, fmt.Errorf("%w: TSM scopedPDU must not be encrypted", ErrBadScopedPDU)
	}
	// ParseV3 already split the plaintext scopedPDU: m.PDU is the raw
	// inner PDU TLV (context engine ID/name are in m.ContextEngineID /
	// m.ContextName).
	return m.PDU, nil
}

// pduCommon parses PDU fields via the shared msg parser.
func pduCommon(pdu []byte) (msg.PDUFields, bool) {
	_, f, err := msg.ParsePDU(pdu)
	if err != nil {
		return msg.PDUFields{}, false
	}
	return f, true
}

// sinkWriter delivers a datagram to a UDP sink (lazy dial per datagram).
func sinkWrite(addr string, dg []byte) error {
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

// peerOK checks a securityName against the configured allow-list (empty
// list = allow any authenticated peer).
func peerOK(name string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == name {
			return true
		}
	}
	return false
}

// pendingBase tracks one in-flight request awaiting its response.
type pendingBase struct {
	ready chan struct{}
}

// managerPending is one manager-side in-flight request.
type managerPending struct {
	pendingBase
	addr      net.Addr
	ver       int
	community []byte
	clientReq int32
}

// informPending tracks an inform awaiting its response (by tunnel corrID):
// the device's original req-id is remembered for the response echo; ver,
// community and addr rebuild the clear response for the sender (best-effort:
// answered at the most recent clear inform sender).
type informPending struct {
	pendingBase
	addr      net.Addr
	req       int32
	ver       int
	community string
}

// ManagerTranslator is the manager-side TSM engine: clear SNMP from
// managers is wrapped in v3 TSM frames over the tunnel; device
// notifications arriving from the tunnel are delivered to the sink.
type ManagerTranslator struct {
	cfg   config.ManagerRole
	sec   config.Security
	sess  FrameSink
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	msgID atomic.Int32
	reqID atomic.Int32
	corr  atomic.Uint32

	pendMu sync.Mutex
	pend   map[uint16]*managerPending
	inform map[uint16]*informPending
	// lastInform is the most recent clear inform sender (stashed by
	// readTraps; informs are answered there since UDP gives no per-message
	// reply address on the response path).
	lastInform net.Addr

	conn     net.PacketConn
	trapConn net.PacketConn

	stop chan struct{}
}

// NewManagerTranslator builds the manager-side TSM engine.
func NewManagerTranslator(cfg config.ManagerRole, sec config.Security, sess FrameSink, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*ManagerTranslator, error) {
	return &ManagerTranslator{
		cfg:    cfg,
		sec:    sec,
		sess:   sess,
		log:    log,
		met:    met,
		filtr:  notifyfilter.From(filt...),
		pend:   make(map[uint16]*managerPending),
		inform: make(map[uint16]*informPending),
		stop:   make(chan struct{}),
	}, nil
}

// Run serves until done is closed.
func (m *ManagerTranslator) Run(done <-chan struct{}) error {
	conn, err := net.ListenPacket("udp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("tsm manager: clear socket: %w", err)
	}
	m.conn = conn
	defer conn.Close()

	if m.cfg.TrapListenAddr != "" {
		tconn, terr := net.ListenPacket("udp", m.cfg.TrapListenAddr)
		if terr != nil {
			return fmt.Errorf("tsm manager: trap socket: %w", terr)
		}
		m.trapConn = tconn
		defer tconn.Close()
		go m.readTraps()
	}

	respCh, cancelResp := m.sess.Subscribe(msgTypeRESP)
	defer cancelResp()
	notCh, cancelNotif := m.sess.Subscribe(msgTypeNOTIF)
	defer cancelNotif()

	go m.readClear()

	for {
		select {
		case <-done:
			close(m.stop)
			return nil
		case f, ok := <-respCh:
			if !ok {
				return nil
			}
			if f.Flags&tunnel.FlagInform != 0 {
				m.handleTunnelInformResp(f)
			} else {
				m.handleTunnelResponse(f)
			}
		case f, ok := <-notCh:
			if !ok {
				return nil
			}
			m.handleTunnelNotif(f)
		}
	}
}

// readClear serves clear requests from managers.
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
		m.handleClearRequest(dg, addr)
	}
}

// handleClearRequest wraps a clear v1/v2c request into a TSM frame.
func (m *ManagerTranslator) handleClearRequest(dg []byte, addr net.Addr) {
	ver, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		m.log.Debug("tsm manager: undecodable clear request", zap.Error(err))
		return
	}
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsGet(info.PDUType) && !msg.IsGetNext(info.PDUType) &&
		!msg.IsSet(info.PDUType) && !msg.IsGetBulk(info.PDUType) {
		return // only requests are proxied
	}
	fields, ok := pduCommon(pduTLV)
	if !ok {
		m.log.Debug("tsm manager: malformed PDU")
		return
	}

	corrID := uint16(m.corr.Add(1))
	msgID := m.msgID.Add(1)
	reqID := m.reqID.Add(1)

	pend := &managerPending{
		pendingBase: pendingBase{ready: make(chan struct{})},
		addr:        addr,
		ver:         ver,
		community:   community,
		clientReq:   fields.ReqID,
	}
	m.pendMu.Lock()
	m.pend[corrID] = pend
	m.pendMu.Unlock()

	// TSM has no per-request engine semantics: the context engine ID is
	// empty (agent-side local context).
	out, err := wrapTSM(msgID, reqID, pduTLV[0], fields.Varbinds, nil, msg.MsgFlagReportable, "")
	if err != nil {
		m.dropPending(corrID)
		return
	}
	if err := m.sess.Send(context.Background(), tunnel.TypeREQ, 0, corrID, out); err != nil {
		m.dropPending(corrID)
		return
	}
	if m.met != nil {
		m.met.ReqForwarded.Inc()
	}

	go func() {
		select {
		case <-time.After(reqTimeout):
			m.dropPending(corrID)
		case <-pend.ready:
		}
	}()
}

func (m *ManagerTranslator) dropPending(corrID uint16) {
	m.pendMu.Lock()
	delete(m.pend, corrID)
	m.pendMu.Unlock()
}

// handleTunnelResponse unwraps a TSM response and delivers it to the
// originating manager.
func (m *ManagerTranslator) handleTunnelResponse(f *tunnel.Frame) {
	data, err := msg.ParseV3(f.Payload)
	if err != nil {
		m.log.Debug("tsm manager: undecodable v3 from tunnel", zap.Error(err))
		return
	}
	if data.Header.SecModel != msg.SecurityModelTSM {
		return
	}
	pdu, err := unwrapTSM(data)
	if err != nil {
		m.log.Debug("tsm manager: bad response PDU", zap.Error(err))
		return
	}
	if len(pdu) == 0 || pdu[0] != msg.PDUGetResponse {
		return
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		return
	}

	m.pendMu.Lock()
	pend, ok := m.pend[f.CorrID]
	if ok {
		delete(m.pend, f.CorrID)
	}
	m.pendMu.Unlock()
	if !ok {
		return
	}
	close(pend.ready)

	resp := msg.BuildPDU(msg.PDUGetResponse, pend.clientReq, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(pend.ver, pend.community, resp)
	if err != nil {
		return
	}
	if _, err := m.conn.WriteTo(out, pend.addr); err != nil {
		m.log.Debug("tsm manager: response delivery failed", zap.Error(err))
	}
}

// lastInformAddr returns the address of the most recent clear inform sender
// (stashed by readTraps; nil when unknown).
func (m *ManagerTranslator) lastInformAddr() net.Addr {
	m.pendMu.Lock()
	defer m.pendMu.Unlock()
	return m.lastInform
}

// handleTunnelInformResp translates an agent-side inform GetResponse (which
// arrives as a RESP frame flagged FlagInform) back into a clear inform
// response for the originating device.
func (m *ManagerTranslator) handleTunnelInformResp(f *tunnel.Frame) {
	m.pendMu.Lock()
	ip, ok := m.inform[f.CorrID]
	if ok {
		delete(m.inform, f.CorrID)
	}
	m.pendMu.Unlock()
	if !ok {
		m.log.Debug("tsm manager: inform response with no pending inform", zap.Uint16("corrID", f.CorrID))
		return
	}

	data, err := msg.ParseV3(f.Payload)
	if err != nil {
		m.log.Debug("tsm manager: undecodable v3 inform response", zap.Error(err))
		return
	}
	if data.Header.SecModel != msg.SecurityModelTSM {
		return
	}
	pdu, err := unwrapTSM(data)
	if err != nil {
		m.log.Debug("tsm manager: bad inform response PDU", zap.Error(err))
		return
	}
	if len(pdu) == 0 || pdu[0] != msg.PDUGetResponse {
		return
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		return
	}

	req := ip.req
	if fields.ReqID != 0 {
		req = fields.ReqID
	}
	resp := msg.BuildPDU(msg.PDUGetResponse, req, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	out, err := msg.BuildV1V2c(ip.ver, []byte(ip.community), resp)
	if err != nil {
		return
	}
	if udp, ok2 := ip.addr.(*net.UDPAddr); ok2 {
		if _, err := m.conn.WriteTo(out, udp); err != nil {
			m.log.Debug("tsm manager: inform response delivery failed", zap.Error(err))
		}
	}
}

// readTraps serves clear traps/informs from local devices.
func (m *ManagerTranslator) readTraps() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.trapConn.ReadFrom(buf)
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
		// stash the sender for inform responses (best-effort: informs are
		// answered at the most recent sender, matching the relay design).
		if info, perr := msg.Peek(dg); perr == nil && msg.IsInform(info.PDUType) {
			m.pendMu.Lock()
			m.lastInform = addr
			m.pendMu.Unlock()
		}
		m.handleClearTrap(dg)
	}
}

// handleClearTrap ships a local device notification over the tunnel.
func (m *ManagerTranslator) handleClearTrap(dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsTrap(info.PDUType) && !msg.IsInform(info.PDUType) {
		return
	}
	if m.filtr != nil {
		oid, ok := msg.TrapOID(dg)
		if !ok || !m.filtr.Allowed(oid) {
			if m.met != nil {
				m.met.NotifsFiltered.Inc()
			}
			m.log.Debug("tsm manager: notification filtered", zap.String("trap_oid", oid))
			return
		}
	}
	_, community, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}
	ver := msg.Version2c
	if info.Version == msg.Version1 {
		ver = msg.Version1
	}

	var pduType uint8
	var varbinds []byte
	isInform := msg.IsInform(info.PDUType)
	if info.PDUType == msg.PDUTrap {
		// v1 trap -> v2 trap per RFC 2576 3.1
		trap, err := msg.SplitV1Trap(pduTLV)
		if err != nil {
			return
		}
		vb, err := msg.V1TrapToV2(trap, nil, true)
		if err != nil {
			return
		}
		pduType = msg.PDUSNMPv2Trap
		varbinds = vb
	} else {
		pduType = info.PDUType
		fields, ok := pduCommon(pduTLV)
		if !ok {
			return
		}
		varbinds = fields.Varbinds
	}

	corrID := uint16(m.corr.Add(1))
	// informs preserve the device's req-id end-to-end (the agent echoes it
	// and the inform response path relays it back to the device)
	reqID := m.reqID.Add(1)
	if isInform {
		reqID = info.RequestID
	}
	out, err := wrapTSM(m.msgID.Add(1), reqID, pduType, varbinds, nil, msg.MsgFlagReportable, "")
	if err != nil {
		return
	}

	if isInform {
		ip := &informPending{
			pendingBase: pendingBase{ready: make(chan struct{})},
			req:         info.RequestID,
			ver:         ver,
			community:   string(community),
			addr:        m.lastInformAddr(),
		}
		m.pendMu.Lock()
		m.inform[corrID] = ip
		m.pendMu.Unlock()
		flags := uint8(tunnel.FlagInform)
		_ = m.sess.Send(context.Background(), tunnel.TypeNOTIF, flags, corrID, out)
		go func() {
			select {
			case <-time.After(reqTimeout):
				m.pendMu.Lock()
				delete(m.inform, corrID)
				m.pendMu.Unlock()
			case <-ip.ready:
			}
		}()
		return
	}
	_ = m.sess.Send(context.Background(), tunnel.TypeNOTIF, 0, corrID, out)
	if m.met != nil {
		m.met.NotifsRelayed.Inc()
	}
}

// handleTunnelNotif delivers device notifications from the tunnel to the
// configured sink (as v2c datagrams).
func (m *ManagerTranslator) handleTunnelNotif(f *tunnel.Frame) {
	data, err := msg.ParseV3(f.Payload)
	if err != nil {
		return
	}
	pdu, err := unwrapTSM(data)
	if err != nil {
		return
	}
	if len(pdu) == 0 {
		return
	}

	// deliver to the sink as v2c (when configured)
	if m.cfg.TrapSinkAddr != "" {
		dg, err := msg.BuildV1V2c(msg.Version2c, []byte(trapCommunity(m.sec.TrapCommunity)), pdu)
		if err != nil {
			return
		}
		if err := sinkWrite(m.cfg.TrapSinkAddr, dg); err != nil {
			m.log.Warn("tsm manager: trap sink delivery failed", zap.Error(err))
			return
		}
		if m.met != nil {
			m.met.NotifsRelayed.Inc()
		}
	}

	// inform: answer with a GetResponse TSM frame echoing the req-id,
	// securityName and security-level flags (TSM response echo rule)
	if pdu[0] == msg.PDUInformRequest {
		fields, ok := pduCommon(pdu)
		if !ok {
			return
		}
		out, err := wrapTSM(data.Header.MsgID, fields.ReqID, msg.PDUGetResponse, fields.Varbinds,
			data.ContextEngineID, data.Header.MsgFlags|msg.MsgFlagReportable, data.USM.UserName)
		if err != nil {
			return
		}
		_ = m.sess.Send(context.Background(), msgTypeRESP, tunnel.FlagInform, f.CorrID, out)
	}
}

// trapCommunity resolves the sink community.
func trapCommunity(cfg string) string {
	if cfg != "" {
		return cfg
	}
	return "public"
}
