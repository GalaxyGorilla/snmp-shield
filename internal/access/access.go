// Package access implements the front-leg access policy shared by every
// ingress point: a client IP allow-list, a per-client request rate limit,
// and an OID-scoped write policy (read-only mode / allowed write subtrees).
//
// The three parts are independent and each is optional. A nil *Policy
// allows everything: callers never test for nil, mirroring the
// notification-filter pattern (no restriction configured = no
// restriction), and a reload swaps the whole immutable Policy atomically
// through a Holder.
//
// Scope: the write policy inspects the SNMP PDU, so it governs v1/v2c
// requests and the decrypted inner PDU of the gateway/translate modes. A
// passthrough proxy forwards v3 messages opaquely and therefore cannot
// see (let alone police) a v3 SET — that is inherent to passthrough, not
// a gap in this package.
package access

import (
	"net"
	"sync/atomic"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// Policy is one compiled, immutable access policy. Build it with New and
// swap it through a Holder on reload; never mutate it in place.
type Policy struct {
	clients *List
	rate    *Limit
	writes  *WritePolicy
}

// New compiles a policy from its parts. allow is the client allow-list
// (bare IPs or CIDR ranges; empty = every client). ratePerSec is the
// per-client request limit (<=0 = unlimited). writes governs writes;
// nil means every write is allowed.
func New(allow []string, ratePerSec int, writes *WritePolicy) (*Policy, error) {
	clients, err := NewList(allow)
	if err != nil {
		return nil, err
	}
	return &Policy{
		clients: clients,
		rate:    NewLimit(ratePerSec),
		writes:  writes,
	}, nil
}

// AllowClient reports whether a request from ip is admitted by the client
// allow-list. A nil policy allows every client.
func (p *Policy) AllowClient(ip net.IP) bool {
	if p == nil {
		return true
	}
	return p.clients.Allowed(ip)
}

// AllowRate reports whether a request from ip is admitted by the
// per-client rate limit, consuming one token when it is. A nil policy
// allows every request.
func (p *Policy) AllowRate(ip net.IP) bool {
	if p == nil {
		return true
	}
	return p.rate.Allow(ip)
}

// AllowWrite reports whether the request PDU (raw PDU TLV) may be relayed
// to the device. Non-SET PDUs are always allowed — the policy governs
// writes only. A nil policy allows every write.
func (p *Policy) AllowWrite(pdu []byte) bool {
	if p == nil {
		return true
	}
	return p.writes.Allowed(pdu)
}

// ReadOnly reports whether the policy forbids all writes (observability
// and reload logging).
func (p *Policy) ReadOnly() bool {
	return p != nil && p.writes.ReadOnly()
}

// WritePolicyRules returns the number of write rules (reload logging).
func (p *Policy) WritePolicyRules() int {
	if p == nil {
		return 0
	}
	return p.writes.Len()
}

// Decision is the outcome of a front-leg access check.
type Decision int

const (
	// Allowed means the request may proceed.
	Allowed Decision = iota
	// DeniedClient means the client IP is not on the allow-list.
	DeniedClient
	// DeniedRate means the client exceeded its request rate.
	DeniedRate
	// DeniedWrite means the SET is outside the write policy.
	DeniedWrite
)

// Check runs the client and rate checks for one datagram from ip,
// consuming a rate token when the client is admitted.
func (p *Policy) Check(ip net.IP) Decision {
	if p == nil {
		return Allowed
	}
	if !p.AllowClient(ip) {
		return DeniedClient
	}
	if !p.AllowRate(ip) {
		return DeniedRate
	}
	return Allowed
}

// IPOf extracts the IP address from a net.Addr. It returns nil when the
// address carries none (a non-IP transport), which a policy treats as
// "cannot judge": the allow-list then rejects it, because an unidentifiable
// peer must never be admitted.
func IPOf(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}

// DenyResponse builds the clear v1/v2c response that tells a manager its
// SET was refused by the write policy. The answer is notWritable, which v1
// cannot express, so ErrorStatusFor maps it to noSuchName there. It
// reports false when the request PDU cannot be decoded (nothing sensible
// to answer).
func DenyResponse(version int, community []byte, pdu []byte) ([]byte, bool) {
	_, f, err := msg.ParsePDU(pdu)
	if err != nil {
		return nil, false
	}
	status, index := msg.ErrorStatusFor(version, msg.ErrStatusNotWritable)
	resp := msg.BuildPDU(msg.PDUGetResponse, f.ReqID, status, index, f.Varbinds)
	out, err := msg.BuildV1V2c(version, community, resp)
	if err != nil {
		return nil, false
	}
	return out, true
}

// Holder is an atomically swappable *Policy. A running proxy reads
// through Get() on every datagram, so a SIGHUP reload takes effect for the
// next packet without touching listeners or sessions.
//
// A nil *Holder reads as a nil *Policy, which allows everything; callers
// therefore only need "pol := holder.Get()" and the nil-safe methods.
type Holder struct {
	p atomic.Pointer[Policy]
}

// NewHolder wraps a policy (which may be nil).
func NewHolder(p *Policy) *Holder {
	h := &Holder{}
	h.p.Store(p)
	return h
}

// Get returns the current policy, or nil when none is installed.
func (h *Holder) Get() *Policy {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// Store installs a new policy. A nil policy restores allow-everything.
func (h *Holder) Store(p *Policy) {
	if h == nil {
		return
	}
	h.p.Store(p)
}
