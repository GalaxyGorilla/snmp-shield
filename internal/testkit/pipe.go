package testkit

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
)

// Pipe is one end of an in-memory tunnel. It satisfies the FrameSink
// interface both translators use (Send/Subscribe) plus PeerCerts, so a
// manager-side and an agent-side translator can be wired together without
// DTLS.
//
// Two behaviours are deliberately faithful to the real tunnel, because
// getting them wrong makes tests flake instead of fail:
//
//   - A frame sent before the peer subscribed is QUEUED and delivered when
//     the subscription appears. The real session buffers; a shim that drops
//     such frames turns a startup race into a lost trap (this was a ~20%
//     flake in the TSM trap tests).
//   - Send is synchronous and never drops. Dropping "because the buffer was
//     full" hides backpressure bugs.
type Pipe struct {
	other *Pipe

	mu      sync.Mutex
	subs    map[uint8][]chan *tunnel.Frame
	pending map[uint8][]*tunnel.Frame

	peerCerts []*x509.Certificate
}

// NewPipePair returns two connected ends. peerCerts is what the agent end
// reports as the tunnel peer's certificate chain (nil = no certificate,
// which is the untrusted-peer case).
func NewPipePair(t testing.TB, peerCerts []*x509.Certificate) (client, server *Pipe) {
	t.Helper()
	client = &Pipe{subs: map[uint8][]chan *tunnel.Frame{}, pending: map[uint8][]*tunnel.Frame{}}
	server = &Pipe{subs: map[uint8][]chan *tunnel.Frame{}, pending: map[uint8][]*tunnel.Frame{}}
	client.other = server
	server.other = client
	// The client sees the server's certificate; the server sees the
	// client's. Tests that care about the peer identity attach it to the
	// end that should report it.
	client.peerCerts = peerCerts
	server.peerCerts = peerCerts
	return client, server
}

// Subscribe returns a channel for one frame type and a cancel function.
func (p *Pipe) Subscribe(ftype uint8) (<-chan *tunnel.Frame, func()) {
	ch := make(chan *tunnel.Frame, 128)
	p.mu.Lock()
	for _, f := range p.pending[ftype] {
		ch <- f
	}
	delete(p.pending, ftype)
	p.subs[ftype] = append(p.subs[ftype], ch)
	p.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			list := p.subs[ftype]
			for i, c := range list {
				if c == ch {
					p.subs[ftype] = append(list[:i], list[i+1:]...)
					break
				}
			}
			close(ch)
		})
	}
	return ch, cancel
}

// Send delivers the frame to the other end. No subscribers yet means the
// frame is queued (see the type comment).
func (p *Pipe) Send(_ context.Context, typ, flags uint8, corrID uint16, payload []byte) error {
	o := p.other
	if o == nil {
		return nil
	}
	f := &tunnel.Frame{Type: typ, Flags: flags, CorrID: corrID, Payload: append([]byte(nil), payload...)}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.subs[typ]) == 0 {
		o.pending[typ] = append(o.pending[typ], f)
		return nil
	}
	for _, ch := range o.subs[typ] {
		ch <- f
	}
	return nil
}

// PeerCerts returns the configured peer certificate chain.
func (p *Pipe) PeerCerts() []*x509.Certificate { return p.peerCerts }

// SetPeerCerts changes what this end reports about its peer (used to model
// a reconnecting tunnel with a different identity).
func (p *Pipe) SetPeerCerts(certs []*x509.Certificate) { p.peerCerts = certs }

// Pending reports how many frames are queued for a frame type because the
// far end has not subscribed yet. Tests use it to prove the queue drains.
func (p *Pipe) Pending(ftype uint8) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending[ftype])
}
