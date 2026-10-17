// Package passthrough, agent side: accepts tunnel connections, forwards
// requests to the real SNMP agent, relays responses back over the
// tunnel, and ships device notifications to the manager side.
package passthrough

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/config"
	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/GalaxyGorilla/snmp-proxy/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-proxy/internal/observ"
	"github.com/GalaxyGorilla/snmp-proxy/internal/tunnel"
	"go.uber.org/zap"
)

// Agent is the agent-side forwarder: tunnel REQ frames -> real agent;
// agent responses -> tunnel RESP frames; device notifications ->
// tunnel NOTIF frames; informs wait for their response.
type Agent struct {
	cfg   config.AgentRole
	sess  *tunnel.Session
	log   *zap.Logger
	met   *observ.Metrics
	filtr *notifyfilter.Filter // notification filter (nil = allow all)

	agentConn *net.UDPConn // socket toward the real agent
	trapConn  *net.UDPConn // clear notification listener for devices

	reqMu   sync.Mutex
	reqPend map[uint16]*reqPend // corrID -> pending agent request
	reqIDs  map[int32][]uint16  // agent requestID -> pending corrIDs (v1/v2c)

	notifMu   sync.Mutex
	notifPend map[uint16]*notifPend // corrID -> pending inform

	agentAddrVal *net.UDPAddr

	nextID atomic.Uint32

	stop chan struct{}
}

// reqPend tracks one request sent to the real agent.
type reqPend struct {
	ready chan struct{}
	resp  []byte
}

// notifPend tracks one inform awaiting its response.
type notifPend struct {
	ready chan struct{}
	resp  []byte
}

// NewAgent creates the agent-side forwarder.
func NewAgent(cfg config.AgentRole, sess *tunnel.Session, log *zap.Logger, met *observ.Metrics, filt ...*notifyfilter.Filter) *Agent {
	aaddr, err := net.ResolveUDPAddr("udp", cfg.AgentAddr)
	if err != nil {
		// Deferred to Run(); the config validation already required it.
		aaddr = &net.UDPAddr{}
	}
	return &Agent{
		cfg:          cfg,
		sess:         sess,
		log:          log,
		met:          met,
		filtr:        notifyfilter.From(filt...),
		reqPend:      make(map[uint16]*reqPend),
		reqIDs:       make(map[int32][]uint16),
		notifPend:    make(map[uint16]*notifPend),
		agentAddrVal: aaddr,
		stop:         make(chan struct{}),
	}
}

// Run starts the agent-side forwarder.
func (a *Agent) Run(ctx context.Context) error {
	aaddr, err := net.ResolveUDPAddr("udp", a.cfg.AgentAddr)
	if err != nil {
		return fmt.Errorf("resolve agent addr: %w", err)
	}
	a.agentAddrVal = aaddr
	a.agentConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("bind toward agent: %w", err)
	}
	defer a.agentConn.Close()

	if a.cfg.TrapListenAddr != "" {
		taddr, rerr := net.ResolveUDPAddr("udp", a.cfg.TrapListenAddr)
		if rerr != nil {
			return fmt.Errorf("resolve trap listen addr: %w", rerr)
		}
		a.trapConn, err = net.ListenUDP("udp", taddr)
		if err != nil {
			return fmt.Errorf("listen trap udp %s: %w", a.cfg.TrapListenAddr, err)
		}
		defer a.trapConn.Close()
	}

	reqCh, cancelReq := a.sess.Subscribe(tunnel.TypeREQ)
	notifAckCh, cancelNotifAck := a.sess.Subscribe(tunnel.TypeRESP)
	defer cancelReq()
	defer cancelNotifAck()

	// Tunnel REQ frames -> real agent.
	go a.reqLoop(reqCh)
	// Tunnel RESP frames are inform responses from the manager side.
	go a.notifRespLoop(notifAckCh)

	errCh := make(chan error, 2)
	go func() { errCh <- a.readAgent() }()
	if a.trapConn != nil {
		go func() { errCh <- a.serveClearTraps() }()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// Close releases resources.
func (a *Agent) Close() {
	close(a.stop)
	if a.agentConn != nil {
		_ = a.agentConn.Close()
	}
	if a.trapConn != nil {
		_ = a.trapConn.Close()
	}
}

// reqLoop handles tunnel REQ frames: forwards them to the real agent.
func (a *Agent) reqLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		payload := append([]byte(nil), f.Payload...)
		corrID := f.CorrID
		a.reqMu.Lock()
		a.reqPend[corrID] = &reqPend{ready: make(chan struct{})}
		a.reqMu.Unlock()

		// Record the requestID for v1/v2c response matching.
		if info, perr := msg.Peek(payload); perr == nil && info.Version != msg.Version3 {
			a.reqMu.Lock()
			a.reqIDs[info.RequestID] = append(a.reqIDs[info.RequestID], corrID)
			a.reqMu.Unlock()
		}

		if _, err := a.agentConn.WriteToUDP(payload, a.agentAddrVal); err != nil {
			a.reqMu.Lock()
			delete(a.reqPend, corrID)
			a.reqMu.Unlock()
			if a.met != nil {
				a.met.ReqErrors.Inc()
			}
			a.log.Warn("forward to agent failed", zap.Error(err))
			continue
		}
		// Response timeout: real agent unreachable -> manager retransmits.
		go a.awaitAgentResp(corrID)
	}
}

// awaitAgentResp drops a pending agent request after a timeout.
func (a *Agent) awaitAgentResp(corrID uint16) {
	select {
	case <-time.After(15 * time.Second):
		a.reqMu.Lock()
		delete(a.reqPend, corrID)
		a.reqMu.Unlock()
	case <-a.stop:
	}
}

// readAgent reads responses from the real agent and matches them to
// pending tunnel requests, sending each back over the tunnel.
func (a *Agent) readAgent() error {
	buf := make([]byte, 65536)
	for {
		n, _, err := a.agentConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-a.stop:
				return nil
			default:
			}
			return fmt.Errorf("agent read: %w", err)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])

		corrID, ok := a.matchResponse(payload)
		if !ok {
			// Unsolicited or late response: drop.
			if a.met != nil {
				a.met.DropTotal.Inc()
			}
			continue
		}
		a.sendRESP(corrID, payload)
	}
}

// matchResponse finds the pending corrID for a response datagram.
// v1/v2c responses are matched by requestID recorded when the request
// was forwarded. v3 responses are opaque; requests per engine are
// serialized so the oldest pending entry wins.
func (a *Agent) matchResponse(payload []byte) (uint16, bool) {
	info, perr := msg.Peek(payload)
	a.reqMu.Lock()
	defer a.reqMu.Unlock()

	if perr == nil && info.Version != msg.Version3 {
		// v1/v2c: match by requestID.
		if ids, ok := a.reqIDs[info.RequestID]; ok && len(ids) > 0 {
			corrID := ids[0]
			a.reqIDs[info.RequestID] = ids[1:]
			if len(a.reqIDs[info.RequestID]) == 0 {
				delete(a.reqIDs, info.RequestID)
			}
			return corrID, true
		}
		return 0, false
	}
	// v3 or unparseable: oldest pending entry (requests serialize per
	// engine on the clear leg).
	for corrID := range a.reqPend {
		return corrID, true
	}
	return 0, false
}

// sendRESP sends a RESP frame back over the tunnel.
func (a *Agent) sendRESP(corrID uint16, payload []byte) {
	if a.met != nil {
		a.met.BytesSent.Add(float64(len(payload)))
	}
	if err := a.sess.Send(a.bgctx(), tunnel.TypeRESP, 0, corrID, payload); err != nil {
		if a.met != nil {
			a.met.ReqErrors.Inc()
		}
		a.log.Warn("send response over tunnel", zap.Error(err))
	}
	a.reqMu.Lock()
	if p, ok := a.reqPend[corrID]; ok {
		close(p.ready)
		delete(a.reqPend, corrID)
	}
	a.reqMu.Unlock()
}

// serveClearTraps reads device notifications and ships them over the
// tunnel as NOTIF frames; informs wait for the manager-side response.
func (a *Agent) serveClearTraps() error {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := a.trapConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-a.stop:
				return nil
			default:
			}
			return fmt.Errorf("trap read: %w", err)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])

		info, perr := msg.Peek(payload)
		isInform := perr == nil && msg.IsInform(info.PDUType)
		if a.filtr != nil && (isInform || (perr == nil && msg.IsTrap(info.PDUType))) {
			oid, ok := msg.TrapOID(payload)
			if !ok || !a.filtr.Allowed(oid) {
				if a.met != nil {
					a.met.NotifsFiltered.Inc()
				}
				a.log.Debug("notification filtered",
					zap.String("trap_oid", oid), zap.String("addr", raddr.String()))
				continue
			}
		}
		flags := uint8(0)
		corrID := uint16(a.nextID.Add(1))
		if isInform {
			a.notifMu.Lock()
			a.notifPend[corrID] = &notifPend{ready: make(chan struct{})}
			a.notifMu.Unlock()
			flags = tunnel.FlagInform
		}
		if a.met != nil {
			a.met.NotifsRelayed.Inc()
		}
		if serr := a.sess.Send(a.bgctx(), tunnel.TypeNOTIF, flags, corrID, payload); serr != nil {
			if a.met != nil {
				a.met.DropTotal.Inc()
			}
			continue
		}
		if isInform {
			go a.awaitInformResp(corrID)
		}
	}
}

// awaitInformResp times out a pending inform after 15s.
func (a *Agent) awaitInformResp(corrID uint16) {
	select {
	case <-time.After(15 * time.Second):
		a.notifMu.Lock()
		delete(a.notifPend, corrID)
		a.notifMu.Unlock()
	case <-a.stop:
	}
}

// notifRespLoop handles tunnel RESP frames that are inform responses.
func (a *Agent) notifRespLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		a.notifMu.Lock()
		p, ok := a.notifPend[f.CorrID]
		if ok {
			p.resp = append([]byte(nil), f.Payload...)
			close(p.ready)
		}
		a.notifMu.Unlock()
	}
}

// bgctx returns a context tied to the stop channel.
func (a *Agent) bgctx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-a.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}
