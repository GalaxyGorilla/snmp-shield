// tsm_gateway.go: single-box TSM gateway role (RFC 6353). The front leg
// is a raw-mode DTLS listener: one SNMP datagram equals one DTLS record
// (no frame layer). The DTLS handshake IS the SNMP authentication: the
// peer certificate chain maps to a securityName (leaf CN, per RFC 5591),
// allow-listed via security.tsm_identities. Authenticated requests are
// relayed as clear v1/v2c to the legacy agent; unauthenticated or
// non-DTLS traffic never reaches the legacy device — that rejection is
// the protection. Clear notifications from the legacy network
// (trap_listen_addr) are wrapped into TSM v3 notifications (secModel=4,
// empty securityParameters) and delivered over a DTLS session to the
// manager's TSM trap receiver (trap_sink_addr).
package tsm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/pion/dtls/v3"
	"go.uber.org/zap"
)

// tsmGwPending is one in-flight forwarded request: the DTLS session to
// answer on (a gateway serves many managers concurrently), the req-id
// written downstream, the manager's original request-id (responses must
// echo it — managers validate response request-ids), the manager's
// v3 header msgID (responses must echo it for v3 — net-snmp drops
// responses whose msgID differs from the request's) and the manager's
// contextEngineID (responses must echo it — net-snmp's snmpv3_verify_msg
// compares it, e.g. the RFC 5343 probe marker 0x8000000006).
type tsmGwPending struct {
	ready         chan struct{}
	downReqID     int32
	clientReqID   int32
	clientMsgID   int32
	clientCtxID   []byte
	clientSecName string
	clientFlags   byte
	conn          net.Conn
}

// gwInformPending tracks one inform awaiting the manager's response: the
// local device's address (for the echo) and the device's request-id.
type gwInformPending struct {
	addr     net.Addr
	deviceID int32
}

// TSMGateway is the single-box TSM gateway: a raw DTLS front leg
// (SNMP-over-DTLS, RFC 6353) terminates certificate-based security
// directly from TSM-capable managers; authenticated requests are relayed
// as clear v1/v2c to the legacy agent.
type TSMGateway struct {
	cfg   config.GatewayRole
	sec   config.Security
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	// identity allow-list (from security.tsm_identities / users)
	allowed []string

	msgID atomic.Int32
	reqID atomic.Int32

	pendMu sync.Mutex
	pend   map[int32]*tsmGwPending

	// informs awaiting the manager's response echo
	informMu sync.Mutex
	inform   map[int32]*gwInformPending

	// clear agent socket, trap listener
	agentConn net.PacketConn
	trapConn  net.PacketConn

	// reusable DTLS session to the manager's TSM trap receiver
	sinkMu   sync.Mutex
	sinkConn net.Conn

	// dtls listener for the front leg; dtls sessions to trap sink
	lcfg tunnel.ListenerConfig
	stop chan struct{}
}

// NewTSMGateway builds the single-box TSM gateway. The identity
// allow-list comes from security.tsm_identities, falling back to the
// configured user names.
func NewTSMGateway(cfg config.GatewayRole, sec config.Security, lcfg tunnel.ListenerConfig, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) (*TSMGateway, error) {
	allowed := sec.TSMIdentities
	if len(allowed) == 0 {
		for _, u := range sec.Users {
			allowed = append(allowed, u.Name)
		}
	}
	return &TSMGateway{
		cfg:     cfg,
		sec:     sec,
		lcfg:    lcfg,
		log:     log,
		met:     met,
		filtr:   notifyfilter.From(filt...),
		allowed: allowed,
		pend:    make(map[int32]*tsmGwPending),
		inform:  make(map[int32]*gwInformPending),
		stop:    make(chan struct{}),
	}, nil
}

// Run binds the raw DTLS front leg, the clear agent socket and
// (optionally) the clear trap listener, and serves until done is closed.
func (g *TSMGateway) Run(done <-chan struct{}) error {
	l, err := tunnel.ListenRaw(g.cfg.ListenAddr, g.lcfg)
	if err != nil {
		return fmt.Errorf("tsm gateway: raw DTLS front listener: %w", err)
	}
	defer l.Close()

	agentConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("tsm gateway: clear agent socket: %w", err)
	}
	g.agentConn = agentConn
	defer agentConn.Close()

	if g.cfg.TrapListenAddr != "" {
		tconn, terr := net.ListenPacket("udp", g.cfg.TrapListenAddr)
		if terr != nil {
			return fmt.Errorf("tsm gateway: trap listener: %w", terr)
		}
		g.trapConn = tconn
		defer tconn.Close()
	}

	// unblock Accept on shutdown
	go func() {
		<-done
		l.Close()
	}()

	go g.readAgent()
	if g.trapConn != nil {
		go g.readTraps()
	}

	// serve DTLS sessions concurrently: every TSM manager dials its own
	// session; RFC 6353 session semantics are per-manager.
	defer close(g.stop)
	var wg sync.WaitGroup
	for {
		conn, aerr := l.Accept()
		if aerr != nil {
			// pion/dtls returns its own "udp: listener closed" sentinel
			// (not net.ErrClosed) when the raw front listener is closed —
			// match both so a clean shutdown returns nil.
			closed := errors.Is(aerr, net.ErrClosed) || strings.Contains(aerr.Error(), "listener closed")
			if closed && done != nil {
				select {
				case <-done:
					wg.Wait()
					return nil
				default:
				}
			}
			return fmt.Errorf("tsm gateway: front accept: %w", aerr)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.serveFront(conn)
		}()
	}
}

// serveFront serves one raw DTLS front-leg session: each Read is exactly
// one SNMP datagram (DTLS preserves record boundaries), so no framing and
// no stream buffering apply. TSM messages carry secModel=4 with an empty
// securityParameters field per RFC 5591; responses go back on the same
// session.
func (g *TSMGateway) serveFront(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		dg := append([]byte{}, buf[:n]...)
		g.handleFrontDatagram(conn, dg)
	}
}

// handleFrontDatagram processes one SNMP-over-DTLS datagram: validate the
// peer certificate (the handshake is the authentication), unwrap the TSM
// v3 message, and relay the inner PDU as clear v1/v2c to the legacy
// agent.
func (g *TSMGateway) handleFrontDatagram(conn net.Conn, dg []byte) {
	name, err := securityNameFromCerts(peerCertsOf(conn))
	if err != nil {
		g.log.Warn("tsm gateway: peer rejected", zap.Error(err))
		if g.met != nil {
			g.met.DropTotal.Inc()
		}
		return
	}
	if !peerOK(name, g.allowed) {
		g.log.Warn("tsm gateway: peer identity not allowed", zap.String("peer", name))
		if g.met != nil {
			g.met.DropTotal.Inc()
		}
		return
	}
	m, err := msg.ParseV3(dg)
	if err != nil {
		g.log.Debug("tsm gateway: undecodable v3 from front leg", zap.Error(err))
		g.drop()
		return
	}
	pdu, err := unwrapTSM(m)
	if err != nil {
		g.log.Debug("tsm gateway: bad TSM request", zap.Error(err))
		g.drop()
		return
	}
	if len(pdu) == 0 || !msg.IsGet(pdu[0]) && !msg.IsGetNext(pdu[0]) &&
		!msg.IsSet(pdu[0]) && !msg.IsGetBulk(pdu[0]) {
		return
	}
	fields, ok := pduCommon(pdu)
	if !ok {
		g.drop()
		return
	}

	downReqID := g.reqID.Add(1)
	pend := &tsmGwPending{ready: make(chan struct{}), downReqID: downReqID, clientReqID: fields.ReqID, clientMsgID: int32(m.Header.MsgID), clientCtxID: m.ContextEngineID, clientSecName: m.USM.UserName, clientFlags: m.Header.MsgFlags, conn: conn}
	g.pendMu.Lock()
	g.pend[downReqID] = pend
	g.pendMu.Unlock()

	down := msg.BuildPDU(pdu[0], downReqID, fields.ErrStatus, fields.ErrIndex, fields.Varbinds)
	community := g.cfg.AgentCommunity
	if community == "" {
		community = "public"
	}
	downMsg, err := msg.BuildV1V2c(msg.Version2c, []byte(community), down)
	if err != nil {
		g.dropPending(downReqID)
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", g.cfg.AgentAddr)
	if err != nil {
		g.dropPending(downReqID)
		return
	}
	if _, err := g.agentConn.WriteTo(downMsg, udpAddr); err != nil {
		g.dropPending(downReqID)
		return
	}
	if g.met != nil {
		g.met.ReqForwarded.Inc()
	}

	go func() {
		select {
		case <-time.After(reqTimeout):
			g.dropPending(downReqID)
		case <-pend.ready:
		}
	}()
}

func (g *TSMGateway) dropPending(downReqID int32) {
	g.pendMu.Lock()
	delete(g.pend, downReqID)
	g.pendMu.Unlock()
}

// peerCertsOf extracts the peer certificate chain from a raw DTLS/TLS
// conn (tunnel rawListener hands out *dtls.Conn / *tls.Conn directly;
// pion/dtls exposes DER bytes).
func peerCertsOf(conn net.Conn) []*x509.Certificate {
	switch c := conn.(type) {
	case *dtls.Conn:
		st, ok := c.ConnectionState()
		if !ok {
			return nil
		}
		return parseDERCerts(st.PeerCertificates)
	case *tls.Conn:
		return c.ConnectionState().PeerCertificates
	default:
		return nil
	}
}

// parseDERCerts decodes DER-encoded certificates (pion/dtls exposes them
// as raw bytes; same logic as tunnel.parseDERCerts, which is
// package-private there).
func parseDERCerts(der [][]byte) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(der))
	for _, d := range der {
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			return nil
		}
		out = append(out, cert)
	}
	return out
}

// readAgent reads responses from the legacy agent on the clear leg.
func (g *TSMGateway) readAgent() {
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

// handleAgentResponse wraps a clear agent response into a TSM v3 message.
// The response session is the request's DTLS session; since a gateway
// serves many managers, responses are matched to sessions by the
// downstream request-id map: each pending records the session to answer
// on.
func (g *TSMGateway) handleAgentResponse(dg []byte) {
	_, _, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		g.log.Debug("tsm gateway: undecodable response from agent", zap.Error(err))
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

	g.pendMu.Lock()
	pend, ok := g.pend[info.RequestID]
	if ok {
		delete(g.pend, info.RequestID)
	}
	g.pendMu.Unlock()
	if !ok || pend.conn == nil {
		return
	}
	close(pend.ready)

	// Echo the request's msgID/reqID/contextEngineID/securityName/security
	// level: net-snmp's snmpv3_verify_msg validates every one of them.
	flags := pend.clientFlags | msg.MsgFlagReportable
	out, err := wrapTSM(pend.clientMsgID, pend.clientReqID, msg.PDUGetResponse, fields.Varbinds, pend.clientCtxID, flags, pend.clientSecName)
	if err != nil {
		return
	}
	if _, err := pend.conn.Write(out); err != nil {
		g.log.Debug("tsm gateway: response send failed", zap.Error(err))
	}
}

// readTraps reads clear v1/v2c notifications from the legacy network on
// trap_listen_addr.
func (g *TSMGateway) readTraps() {
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
		g.handleClearTrap(dg, addr)
	}
}

// handleClearTrap wraps a clear notification into a TSM v3 message and
// delivers it over a DTLS session to the manager's TSM trap receiver
// (trap_sink_addr). One DTLS session is established lazily and kept for
// reuse. src is the sender's address, needed to echo inform responses
// back to the device.
func (g *TSMGateway) handleClearTrap(dg []byte, src net.Addr) {
	info, err := msg.Peek(dg)
	if err != nil || !msg.IsTrap(info.PDUType) && !msg.IsInform(info.PDUType) {
		return
	}
	if g.filtr != nil {
		oid, ok := msg.TrapOID(dg)
		if !ok || !g.filtr.Allowed(oid) {
			if g.met != nil {
				g.met.NotifsFiltered.Inc()
			}
			g.log.Debug("tsm gateway: notification filtered", zap.String("trap_oid", oid))
			return
		}
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

	out, err := wrapTSM(g.msgID.Add(1), g.reqID.Add(1), pduType, varbinds, nil, msg.MsgFlagReportable, "")
	if err != nil {
		return
	}

	if isInform {
		// RFC 5591: the manager's response must be echoed back to the
		// device as a GetResponse with the device's request-id; the
		// device address is recorded for the echo path.
		ip := &gwInformPending{addr: src, deviceID: info.RequestID}
		g.informMu.Lock()
		g.inform[info.RequestID] = ip
		g.informMu.Unlock()
		go func() {
			g.trapSinkWrite(out)
			<-time.After(reqTimeout)
			g.informMu.Lock()
			delete(g.inform, info.RequestID)
			g.informMu.Unlock()
		}()
	} else {
		go g.trapSinkWrite(out)
	}
}

func (g *TSMGateway) drop() {
	if g.met != nil {
		g.met.DropTotal.Inc()
	}
}

// trapSinkWrite delivers one wrapped notification to the manager's TSM
// trap receiver (trap_sink_addr) over DTLS. The session is dialed lazily
// on first use and kept for reuse; a failed send drops it so the next
// notification redials. Dialer material comes from lcfg (the gateway has
// no Tunnel section of its own — proxy wiring populates it from the same
// cert material as the front leg).
func (g *TSMGateway) trapSinkWrite(dg []byte) {
	g.sinkMu.Lock()
	conn := g.sinkConn
	g.sinkMu.Unlock()
	if conn != nil {
		if _, err := conn.Write(dg); err == nil {
			return
		}
		conn.Close()
		g.sinkMu.Lock()
		g.sinkConn = nil
		g.sinkMu.Unlock()
	}
	d := &tunnel.Dialer{
		Mode:     "dtls",
		CAFile:   g.lcfg.CAFile,
		CertFile: g.lcfg.CertFile,
		KeyFile:  g.lcfg.KeyFile,
		Insecure: g.lcfg.Insecure,
		Timeout:  5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.Dial(ctx, g.cfg.TrapSinkAddr)
	if err != nil {
		g.log.Warn("tsm gateway: trap sink dial failed", zap.String("sink", g.cfg.TrapSinkAddr), zap.Error(err))
		return
	}
	g.sinkMu.Lock()
	g.sinkConn = c
	g.sinkMu.Unlock()
	if _, err := c.Write(dg); err != nil {
		g.log.Debug("tsm gateway: trap sink write failed", zap.Error(err))
	}
}
