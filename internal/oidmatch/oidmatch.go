// Package oidmatch canonicalizes and prefix-matches dotted object
// identifiers. It is the shared primitive behind notification filtering
// and the access policy's OID-scoped write rules: both answer "is this
// OID inside that subtree?" and both must agree on what "inside" means.
package oidmatch

import (
	"fmt"
	"strings"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// Canonical normalizes a dotted OID via a BER round trip, so equivalent
// textual forms collapse to one representation ("1.03.6.1" -> "1.3.6.1",
// ".1.3.6.1" -> "1.3.6.1"). Config values and wire-decoded values are
// then directly comparable.
func Canonical(oid string) (string, error) {
	// A leading dot is a common way to write an absolute OID but
	// msg.EncodeOID takes the bare dotted form.
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if oid == "" {
		return "", fmt.Errorf("empty OID")
	}
	ber, err := msg.EncodeOID(oid)
	if err != nil {
		return "", err
	}
	dotted, err := msg.DecodeOID(ber)
	if err != nil {
		return "", err
	}
	return dotted, nil
}

// Match reports whether oid is prefix itself or lies underneath it.
// Matching is prefix-based on arc boundaries, never on characters:
// "1.3.6.1.4.1.99" matches "1.3.6.1.4.1.99.5" but NOT
// "1.3.6.1.4.1.9999", and "1.3.6.1.4.1" matches both.
//
// Both arguments are expected to be canonical (see Canonical), which is
// how the compiled rule sets are built; an empty prefix matches
// everything so callers can skip the special case.
func Match(prefix, oid string) bool {
	if prefix == "" {
		return true
	}
	if oid == prefix {
		return true
	}
	return strings.HasPrefix(oid, prefix+".")
}
