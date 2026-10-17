// Package notifyfilter provides OID-based allow/deny filtering of SNMP
// notifications (traps/informs) at the relay ingress points. One filter
// holds a list of canonical dotted OID prefixes and an action: "allow"
// forwards only matching notifications, "deny" drops matching ones.
package notifyfilter

import (
	"fmt"
	"strings"

	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
)

// Filter classifies notification trap OIDs against a prefix list.
type Filter struct {
	action string   // "allow" or "deny" ("" = allow)
	oids   []string // canonical dotted OID prefixes
}

// New builds a filter from an action and a list of dotted OID prefixes.
// action is "allow" (default, also ""), "deny"; oids must contain at
// least one OID. Each OID is canonicalized via BER round-trip (leading
// zeros and equivalent forms collapse: "1.03.6.1" -> "1.3.6.1").
func New(action string, oids []string) (*Filter, error) {
	switch action {
	case "", "allow", "deny":
	default:
		return nil, fmt.Errorf("notifyfilter: unknown action %q (want allow or deny)", action)
	}
	if len(oids) == 0 {
		return nil, fmt.Errorf("notifyfilter: at least one OID is required")
	}
	canon := make([]string, 0, len(oids))
	for _, o := range oids {
		ber, err := msg.EncodeOID(o)
		if err != nil {
			return nil, fmt.Errorf("notifyfilter: OID %q: %w", o, err)
		}
		dotted, err := msg.DecodeOID(ber)
		if err != nil {
			return nil, fmt.Errorf("notifyfilter: OID %q: %w", o, err)
		}
		canon = append(canon, dotted)
	}
	return &Filter{action: action, oids: canon}, nil
}

// Allowed reports whether a notification with the given trap OID passes
// the filter. A nil filter allows everything. Matching is prefix-based on
// arc boundaries: "1.3.6.1.4.1" matches "1.3.6.1.4.1.9999" but not
// "1.3.6.1.4.1.9999" against "1.3.6.1.4.1.99" (no partial arcs).
func (f *Filter) Allowed(trapOID string) bool {
	if f == nil {
		return true
	}
	matched := false
	for _, p := range f.oids {
		if trapOID == p || strings.HasPrefix(trapOID, p+".") {
			matched = true
			break
		}
	}
	if f.action == "deny" {
		return !matched
	}
	return matched
}

// From returns the first non-nil filter, or nil. It lets constructors
// accept a variadic filter parameter without changing existing call sites.
func From(filt ...*Filter) *Filter {
	for _, f := range filt {
		if f != nil {
			return f
		}
	}
	return nil
}
