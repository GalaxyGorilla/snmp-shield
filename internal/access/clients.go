package access

import (
	"net"
	"sync"
)

// List is a client IP allow-list: bare addresses and CIDR ranges. A nil
// *List allows every client.
type List struct {
	mu    sync.RWMutex
	ips   []net.IP
	cidrs []*net.IPNet
}

// NewList parses allow-list entries ("10.0.0.5", "10.8.0.0/24", also
// IPv6). An empty entry list returns nil — no restriction. Entries have
// already been validated by config; a parse failure here is reported so a
// programmatic caller notices, but never silently widens the list.
func NewList(entries []string) (*List, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	l := &List{}
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil {
			l.ips = append(l.ips, ip)
			continue
		}
		_, cidr, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		l.cidrs = append(l.cidrs, cidr)
	}
	return l, nil
}

// Allowed reports whether ip passes the allow-list. A nil list allows
// every client.
func (l *List) Allowed(ip net.IP) bool {
	if l == nil {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, allowed := range l.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, cidr := range l.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the number of entries (0 for a nil list).
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.ips) + len(l.cidrs)
}
