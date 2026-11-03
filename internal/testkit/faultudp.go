package testkit

import (
	"net"
	"sync"
	"testing"
	"time"
)

// FaultDirection says which leg of the relay a datagram is on.
type FaultDirection int

const (
	// FaultToUpstream is client (proxy) -> device.
	FaultToUpstream FaultDirection = iota
	// FaultToDownstream is device -> client (proxy).
	FaultToDownstream
)

// FaultAction is what the relay should do with one datagram.
type FaultAction struct {
	Drop      bool
	Duplicate bool
	Delay     time.Duration
}

// FaultFunc decides the action for one datagram. seq starts at 1 and counts
// every datagram on that direction, including ones that are dropped, so a
// test can say "drop the first response" deterministically.
type FaultFunc func(dir FaultDirection, seq int, dg []byte) FaultAction

// FaultyUDPRelay sits between one proxy and one device on loopback and
// applies deterministic loss/duplication/delay. It is the network the Go
// standard library cannot give us: a real WAN is not required to prove that
// pending entries, retries and late responses are handled.
//
// One relay serves one client socket (the proxy's device leg) and one
// upstream device. That is the production shape for a gateway: one device
// socket, many concurrent requests multiplexed by request-id.
type FaultyUDPRelay struct {
	listen   *net.UDPConn
	upstream *net.UDPConn
	fault    FaultFunc

	mu     sync.Mutex
	client *net.UDPAddr

	closed chan struct{}
	wg     sync.WaitGroup
}

// NewFaultyUDPRelay binds a loopback relay in front of upstream and starts
// forwarding. It is closed automatically at test cleanup.
func NewFaultyUDPRelay(t testing.TB, upstream string, fault FaultFunc) *FaultyUDPRelay {
	t.Helper()
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testkit: relay resolve: %v", err)
	}
	listen, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("testkit: relay listen: %v", err)
	}
	uaddr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		_ = listen.Close()
		t.Fatalf("testkit: relay upstream %s: %v", upstream, err)
	}
	up, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		_ = listen.Close()
		t.Fatalf("testkit: relay dial upstream: %v", err)
	}
	if fault == nil {
		fault = func(FaultDirection, int, []byte) FaultAction { return FaultAction{} }
	}
	r := &FaultyUDPRelay{
		listen:   listen,
		upstream: up,
		fault:    fault,
		closed:   make(chan struct{}),
	}
	r.wg.Add(2)
	go r.readClient()
	go r.readUpstream()
	t.Cleanup(r.Close)
	return r
}

// Addr is the address the proxy should be configured to use as its device.
func (r *FaultyUDPRelay) Addr() string { return r.listen.LocalAddr().String() }

// Close stops both loops. Delayed datagrams may still fire once; they write
// to a closed socket and are discarded.
func (r *FaultyUDPRelay) Close() {
	select {
	case <-r.closed:
		return
	default:
		close(r.closed)
	}
	_ = r.listen.Close()
	_ = r.upstream.Close()
	r.wg.Wait()
}

func (r *FaultyUDPRelay) readClient() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	seq := 0
	for {
		n, from, err := r.listen.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		r.mu.Lock()
		r.client = from
		r.mu.Unlock()
		seq++
		r.forward(dg, r.fault(FaultToUpstream, seq, dg), func() {
			_, _ = r.upstream.Write(dg)
		})
	}
}

func (r *FaultyUDPRelay) readUpstream() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	seq := 0
	for {
		n, err := r.upstream.Read(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		r.mu.Lock()
		client := r.client
		r.mu.Unlock()
		if client == nil {
			continue
		}
		seq++
		r.forward(dg, r.fault(FaultToDownstream, seq, dg), func() {
			_, _ = r.listen.WriteToUDP(dg, client)
		})
	}
}

func (r *FaultyUDPRelay) forward(_ []byte, act FaultAction, send func()) {
	if act.Drop {
		return
	}
	deliver := func() {
		send()
		if act.Duplicate {
			send()
		}
	}
	if act.Delay <= 0 {
		deliver()
		return
	}
	time.AfterFunc(act.Delay, deliver)
}
