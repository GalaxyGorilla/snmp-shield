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

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/notifyfilter"
	"github.com/GalaxyGorilla/snmp-shield/internal/observ"
	"github.com/GalaxyGorilla/snmp-shield/internal/safego"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
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
	sinkConn  *net.UDPConn // sink for notifications arriving over the tunnel

	reqMu   sync.Mutex
	reqPend map[uint16]*reqPend // corrID -> pending agent request
	reqIDs  map[int32][]uint16  // agent requestID -> pending corrIDs (v1/v2c)

	notifMu   sync.Mutex
	notifPend map[uint16]*informPend // corrID -> inform awaiting the sink's ack

	agentAddrVal *net.UDPAddr

	nextID atomic.Uint32

	stop chan struct{}

	// bgOnce guards the single send context. It used to be built per send
	// (fresh WithCancel + a watcher goroutine whose cancel was discarded),
	// which leaked one goroutine per request and one per notification for
	// the life of the process. The soak test found it at 50 req/s; on an
	// appliance that is millions of goroutines a day.
	bgOnce sync.Once
	bgCtx  context.Context
}

// reqPend tracks one request sent to the real agent.
type reqPend struct {
	ready chan struct{}
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
		notifPend:    make(map[uint16]*informPend),
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
	if a.cfg.TrapSinkAddr != "" {
		// Notifications arriving from the manager side are already clear
		// v1/v2c datagrams (passthrough forwards bytes, never re-wraps), so
		// the sink is a plain socket: no community rewriting here.
		saddr, rerr := net.ResolveUDPAddr("udp", a.cfg.TrapSinkAddr)
		if rerr != nil {
			return fmt.Errorf("resolve trap sink addr: %w", rerr)
		}
		a.sinkConn, err = net.DialUDP("udp", nil, saddr)
		if err != nil {
			return fmt.Errorf("dial trap sink %s: %w", a.cfg.TrapSinkAddr, err)
		}
		defer a.sinkConn.Close()
	}

	reqCh, cancelReq := a.sess.Subscribe(tunnel.TypeREQ)
	notifCh, cancelNotif := a.sess.Subscribe(tunnel.TypeNOTIF)
	notifAckCh, cancelNotifAck := a.sess.Subscribe(tunnel.TypeRESP)
	defer cancelReq()
	defer cancelNotif()
	defer cancelNotifAck()

	// Tunnel REQ frames -> real agent.
	go a.reqLoop(reqCh)
	// Tunnel NOTIF frames -> the trap sink (the reverse notification
	// direction: a clear notification accepted on the manager side).
	go a.notifLoop(notifCh)
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
//
// It also watches the pending entry's ready channel: without that, every
// answered request kept a goroutine (and its reqPend entry) for the full 15s,
// so the process held rate x 15s goroutines at all times. The soak test's
// goroutine graph is what made it visible.
func (a *Agent) awaitAgentResp(corrID uint16) {
	a.reqMu.Lock()
	p := a.reqPend[corrID]
	a.reqMu.Unlock()
	if p == nil {
		return // answered before this goroutine started
	}
	select {
	case <-p.ready:
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
		safego.Dispatch(a.log, "passthrough agent response", func() { a.handleAgentDatagram(payload) })
	}
}

// handleAgentDatagram matches one agent response to a pending tunnel
// request and ships it back. It runs under safego.Dispatch: a malformed
// response is untrusted input.
func (a *Agent) handleAgentDatagram(payload []byte) {
	corrID, ok := a.matchResponse(payload)
	if !ok {
		// Unsolicited or late response: drop.
		if a.met != nil {
			a.met.DropTotal.Inc()
		}
		return
	}
	a.sendRESP(corrID, payload)
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
		safego.Dispatch(a.log, "passthrough agent trap", func() { a.handleClearTrap(payload, raddr) })
	}
}

// handleClearTrap ships one clear device notification over the tunnel;
// informs wait for the manager-side confirmation.
func (a *Agent) handleClearTrap(payload []byte, raddr *net.UDPAddr) {
	info, perr := msg.Peek(payload)
	if perr != nil || !(msg.IsTrap(info.PDUType) || msg.IsInform(info.PDUType)) {
		// A trap listener accepts notifications and nothing else. Passthrough
		// forwards bytes verbatim, so whatever arrives here would be handed to
		// the far-side sink unexamined — a stray byte from a port probe, a
		// scanner datagram, or a request sent to the wrong port. The
		// translating modes reject the same input at their ingress; this mode
		// has no later parser to notice, so the check has to live here.
		if a.met != nil {
			a.met.DropTotal.Inc()
		}
		if a.log != nil {
			a.log.Debug("notification ingress: not a notification; dropped",
				zap.Int("bytes", len(payload)), zap.String("addr", raddr.String()))
		}
		return
	}
	isInform := msg.IsInform(info.PDUType)
	if a.filtr != nil {
		oid, ok := msg.TrapOID(payload)
		if !ok || !a.filtr.Allowed(oid) {
			if a.met != nil {
				a.met.NotifsFiltered.Inc()
			}
			a.log.Debug("notification filtered",
				zap.String("trap_oid", oid), zap.String("addr", raddr.String()))
			return
		}
	}
	flags := uint8(0)
	corrID := uint16(a.nextID.Add(1))
	if isInform {
		// Tracked only when the inform decodes: a confirmation rebuilt from
		// zero values would look like a valid answer to the device.
		if p, ok := parseInformPend(payload, raddr); ok {
			p.ready = make(chan struct{})
			a.notifMu.Lock()
			a.notifPend[corrID] = p
			a.notifMu.Unlock()
			flags = tunnel.FlagInform
		} else {
			a.log.Warn("device inform is undecodable; relaying it but it cannot be confirmed",
				zap.String("addr", raddr.String()))
		}
	}
	if a.met != nil {
		a.met.NotifsRelayed.Inc()
	}
	if serr := a.sess.Send(a.bgctx(), tunnel.TypeNOTIF, flags, corrID, payload); serr != nil {
		if a.met != nil {
			a.met.DropTotal.Inc()
		}
		if isInform {
			// No frame went out, so no confirmation can ever arrive; drop the
			// entry instead of leaving it for a wait that was never started.
			a.notifMu.Lock()
			delete(a.notifPend, corrID)
			a.notifMu.Unlock()
		}
		return
	}
	if isInform {
		go a.awaitInformResp(corrID)
	}
}

// notifLoop delivers notifications that arrived over the tunnel (accepted by
// the manager side) to the local trap sink, and confirms informs.
//
// Until this loop existed, the agent side had no TypeNOTIF subscriber at all:
// `manager.trap_listen_addr` accepted clear notifications, shipped them across
// the tunnel, and they were discarded at the far end — silent loss, the worst
// shape a trap can fail in.
//
// An inform is confirmed only when it was actually delivered: answering on
// behalf of a sink that does not exist (or refused the write) would tell the
// device its event was recorded when it was not.
func (a *Agent) notifLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		delivered := false
		if a.sinkConn != nil {
			if _, err := a.sinkConn.Write(f.Payload); err != nil {
				a.log.Warn("trap sink write", zap.Error(err))
			} else {
				delivered = true
				if a.met != nil {
					a.met.NotifsRelayed.Inc()
				}
			}
		} else if a.log != nil {
			a.log.Debug("notification from the tunnel dropped: no trap_sink_addr configured")
		}
		if f.Flags&tunnel.FlagInform == 0 || !delivered {
			continue
		}
		// The confirmation carries no payload: the manager side rebuilds the
		// clear GetResponse for the device from the inform it forwarded.
		if err := a.sess.Send(a.bgctx(), tunnel.TypeRESP, tunnel.FlagInform, f.CorrID, nil); err != nil {
			a.log.Warn("send inform confirmation over tunnel", zap.Error(err))
		}
	}
}

// awaitInformResp times out a pending inform after 15s, or returns as soon as
// the manager-side confirmation arrives.
func (a *Agent) awaitInformResp(corrID uint16) {
	a.notifMu.Lock()
	p := a.notifPend[corrID]
	a.notifMu.Unlock()
	if p == nil {
		return // answered before this goroutine started
	}
	select {
	case <-p.ready:
	case <-time.After(15 * time.Second):
		a.notifMu.Lock()
		delete(a.notifPend, corrID)
		a.notifMu.Unlock()
	case <-a.stop:
	}
}

// notifRespLoop handles tunnel RESP frames that are inform responses: it
// rebuilds the clear GetResponse the device expects and sends it FROM the trap
// listener that received the inform (a connected sender drops an answer from
// any other source port). Before this, the response was consumed as a mere
// "no longer pending" signal and the device never heard back at all.
func (a *Agent) notifRespLoop(ch <-chan *tunnel.Frame) {
	for f := range ch {
		a.notifMu.Lock()
		p, ok := a.notifPend[f.CorrID]
		if ok {
			delete(a.notifPend, f.CorrID)
		}
		a.notifMu.Unlock()
		if !ok {
			continue
		}
		if p.ready != nil {
			close(p.ready) // releases the 15s timeout wait
		}
		if p.addr == nil || a.trapConn == nil {
			continue
		}
		resp := msg.BuildPDU(msg.PDUGetResponse, p.reqID, 0, 0, p.varbinds)
		out, err := msg.BuildV1V2c(p.ver, p.community, resp)
		if err != nil {
			a.log.Warn("build inform confirmation", zap.Error(err))
			continue
		}
		if _, werr := a.trapConn.WriteToUDP(out, p.addr); werr != nil {
			a.log.Warn("deliver inform confirmation", zap.Error(werr))
		}
	}
}

// bgctx returns the one send context, cancelled when the agent stops.
//
// Built once: a context (and its watcher goroutine) per send is a leak, not a
// style issue — the tunnel Send is called once per request and once per
// notification.
func (a *Agent) bgctx() context.Context {
	a.bgOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.bgCtx = ctx
		go func() {
			select {
			case <-a.stop:
				cancel()
			case <-ctx.Done():
			}
		}()
	})
	return a.bgCtx
}
