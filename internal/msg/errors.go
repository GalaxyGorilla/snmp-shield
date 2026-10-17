// Package msg: shared BER parse errors for the split/build codec. Kept in
// a separate file so both peek.go and pdu.go can reference them.
package msg

import "errors"

var (
	errShortOID  = errors.New("msg: OID needs at least two arcs")
	errBadOID    = errors.New("msg: bad OID sub-identifier")
	errNoPDU     = errors.New("msg: no PDU after community string")
	errBadPDU    = errors.New("msg: malformed PDU")
	errBadMsg    = errors.New("msg: malformed SNMP message")
	errBadV3     = errors.New("msg: malformed SNMPv3 message")
	errBadUSM    = errors.New("msg: malformed USM security parameters")
	errShortPriv = errors.New("msg: privacy parameters too short")
)
