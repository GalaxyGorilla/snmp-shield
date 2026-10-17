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

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
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
// are empty per RFC 5591. msgID/reqID come from the caller's counters.
func wrapTSM(msgID int32, reqID int32, pduType uint8, pduBody []byte, ctxEngineID []byte, reportable bool) ([]byte, error) {
	pdu := msg.BuildPDU(pduType, reqID, 0, 0, pduBody)
	scoped := msg.BuildScoped(ctxEngineID, []byte{}, pdu)
	flags := uint8(0)
	if reportable {
		flags |= msg.MsgFlagReportable
	}
	return msg.BuildV3(msg.V3Header{
		MsgID:      msgID,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelTSM,
	}, msg.USMParams{}, scoped, nil)
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

// berLen reads length octets at buf (position after the tag).
func berLen(buf []byte) (int, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, ErrBadScopedPDU
	}
	b := buf[0]
	if b < 0x80 {
		return int(b), buf[1:], nil
	}
	if b == 0x80 {
		return 0, nil, ErrBadScopedPDU
	}
	n := int(b & 0x7f)
	if n > 4 || len(buf) < 1+n {
		return 0, nil, ErrBadScopedPDU
	}
	l := 0
	for i := 1; i <= n; i++ {
		l = l<<8 | int(buf[i])
	}
	return l, buf[1+n:], nil
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
	resp  []byte
}

// managerPending is one manager-side in-flight request.
type managerPending struct {
	pendingBase
	addr      net.Addr
	ver       int
	community []byte
	clientReq int32
}

// informPending tracks an inform awaiting its response.
type informPending struct {
	pendingBase
	addr net.Addr
	req  int32
}

// ManagerTranslator is the manager-side TSM engine: clear SNMP from
// managers is wrapped in v3 TSM frames over the tunnel; device
// notifications arriving from the tunnel are delivered to the sink.
type ManagerTranslator struct {
	cfg config.ManagerRole
	sec config.Security
	sess FrameSink
	log  *zap.Logger
	met  *observ.Metrics

	msgID atomic.Int32
	reqID atomic.Int32
	corr  atomic.Uint32

	pendMu sync.Mutex
	pend   map[uint16]*managerPending
	inform map[uint16]*informPending

	conn     net.PacketConn
	trapConn net.PacketConn

	stop chan struct{}
}

// NewManagerTranslator builds the manager-side TSM engine.
func NewManagerTranslator(cfg config.ManagerRole, sec config.Security, sess FrameSink, log *zap.Logger, met *observ.Metrics) (*ManagerTranslator, error) {
	return &ManagerTranslator{
		cfg:    cfg,
		sec:    sec,
		sess:   sess,
		log:    log,
		met:    met,
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
			m.handleTunnelResponse(f)
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
	out, err := wrapTSM(msgID, reqID, pduTLV[0], fields.Varbinds, nil, true)
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

// readTraps serves clear traps/informs from local devices.
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

// handleClearTrap ships a local device notification over the tunnel.
func (m *ManagerTranslator) handleClearTrap(dg []byte) {
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsTrap(info.PDUType) && !msg.IsInform(info.PDUType) {
			return
	}
	_, _, pduTLV, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
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
	out, err := wrapTSM(m.msgID.Add(1), m.reqID.Add(1), pduType, varbinds, nil, true)
	if err != nil {
			return
	}

	if isInform {
		ip := &informPending{
			pendingBase: pendingBase{ready: make(chan struct{})},
			req:         info.RequestID,
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
	if m.cfg.TrapSinkAddr == "" {
		return
	}
	if len(pdu) == 0 {
		return
	}
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

	// inform response path: an inform received from the tunnel is
	// answered by the agent side; nothing to do here.
	_ = f.Flags
}

// trapCommunity resolves the sink community.
func trapCommunity(cfg string) string {
	if cfg != "" {
		return cfg
	}
	return "public"
}
