package access

import (
	"fmt"
	"strconv"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/oidmatch"
)

// WriteRule is one parsed rule: a subtree of object identifiers and the
// verdict for writes inside it.
type WriteRule struct {
	// OID is the canonical dotted subtree root.
	OID string
	// Allow is true for allow rules, false for deny rules.
	Allow bool
}

// WritePolicy is a compiled set of OID-scoped write rules. It answers
// "may this SET touch these objects?" — the coarse read_only switch
// answers "may anyone write at all?".
//
// Evaluation is deny-overrides and allow-must-cover, the same shape as
// the Modbus side's address-scoped policy so operators only learn the
// rule once:
//
//   - a DENY rule matches when ANY requested object lies at or under the
//     rule's subtree (touching one forbidden object is enough to reject
//     the whole SET, so a request can never straddle an allowed and a
//     forbidden subtree);
//   - an ALLOW rule matches only when it covers EVERY requested object;
//   - any matching deny wins; otherwise a covering allow wins; otherwise
//     the policy default applies (deny unless configured otherwise).
//
// Rules are evaluated as a SET, not in order — rule order in the config
// is irrelevant, which makes the policy auditable ("what denies exist?").
//
// A nil *WritePolicy allows every write (no policy configured).
type WritePolicy struct {
	readOnly     bool
	defaultAllow bool
	rules        []WriteRule
}

// NewReadOnly returns the coarse switch: every SET is refused, nothing
// else is affected.
func NewReadOnly() *WritePolicy { return &WritePolicy{readOnly: true} }

// NewWritePolicy compiles OID rules. defaultAllow is the verdict for a
// write no rule covers. A policy with no rules is legal only when it
// allows by default (otherwise it would reject every write — that is what
// read_only is for).
func NewWritePolicy(defaultAllow bool, rules []WriteRule) (*WritePolicy, error) {
	if len(rules) == 0 && !defaultAllow {
		return nil, &RuleError{Index: -1, Msg: "no rules and default deny would block every write (use read_only instead)"}
	}
	canon := make([]WriteRule, 0, len(rules))
	for i, r := range rules {
		oid, err := oidmatch.Canonical(r.OID)
		if err != nil {
			return nil, &RuleError{Index: i, Msg: "OID " + strconv.Quote(r.OID) + ": " + err.Error()}
		}
		canon = append(canon, WriteRule{OID: oid, Allow: r.Allow})
	}
	return &WritePolicy{defaultAllow: defaultAllow, rules: canon}, nil
}

// RuleError reports a bad write-policy rule; Index is its position in the
// config list (-1 for policy-level errors).
type RuleError struct {
	Index int
	Msg   string
}

func (e *RuleError) Error() string {
	if e.Index < 0 {
		return "write policy: " + e.Msg
	}
	return "write policy: rule " + strconv.Itoa(e.Index) + ": " + e.Msg
}

// ReadOnly reports whether the policy refuses all writes.
func (p *WritePolicy) ReadOnly() bool { return p != nil && p.readOnly }

// Len returns the number of rules (0 for a nil policy).
func (p *WritePolicy) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rules)
}

// DefaultAllow reports the verdict for writes no rule covers.
func (p *WritePolicy) DefaultAllow() bool { return p != nil && p.defaultAllow }

// Allowed reports whether the request PDU may be relayed to the device.
// pdus that are not SET requests are always allowed: reads are governed by
// the client allow-list and rate limit, not by this policy.
//
// A SET that cannot be decoded — no varbinds, malformed varbind list,
// undecodable OID — is denied: an unparseable write cannot be authorized.
func (p *WritePolicy) Allowed(pdu []byte) bool {
	if p == nil {
		return true
	}
	if len(pdu) == 0 || pdu[0] != msg.PDUSetRequest {
		return true
	}
	if p.readOnly {
		return false
	}
	oids, ok := setOIDs(pdu)
	if !ok || len(oids) == 0 {
		return false
	}

	// Deny overrides everything: touching one forbidden object rejects
	// the entire SET.
	for _, oid := range oids {
		for _, r := range p.rules {
			if !r.Allow && oidmatch.Match(r.OID, oid) {
				return false
			}
		}
	}

	// An allow only wins when it covers every requested object.
	covered := true
	for _, oid := range oids {
		found := false
		for _, r := range p.rules {
			if r.Allow && oidmatch.Match(r.OID, oid) {
				found = true
				break
			}
		}
		if !found {
			covered = false
			break
		}
	}
	if covered {
		return true
	}
	return p.defaultAllow
}

// setOIDs extracts the object identifiers a SET request touches.
func setOIDs(pdu []byte) ([]string, bool) {
	_, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		return nil, false
	}
	var oids []string
	rest := fields.Varbinds
	for len(rest) > 0 {
		tag, content, next, err := msg.NextTLV(rest)
		if err != nil {
			return nil, false
		}
		rest = next
		if tag != 0x30 {
			// Every varbind is a SEQUENCE; anything else means the
			// list is malformed and the write cannot be judged.
			return nil, false
		}
		// varbind content = OID TLV + value TLV
		oidTag, oidVal, _, err := msg.NextTLV(content)
		if err != nil || oidTag != 0x06 {
			return nil, false
		}
		dotted, err := msg.DecodeOID(oidVal)
		if err != nil {
			return nil, false
		}
		oids = append(oids, dotted)
	}
	return oids, true
}

// ValidateOID reports whether a config OID is a usable subtree root
// (config-level helper so validation and compilation agree on the rule).
func ValidateOID(oid string) error {
	if _, err := oidmatch.Canonical(oid); err != nil {
		return fmt.Errorf("OID %q: %w", oid, err)
	}
	return nil
}
