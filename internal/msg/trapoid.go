// trapoid.go: extract the trap OID of a v1/v2c notification datagram.
// Used by the notification filter to classify clear traps/informs at the
// relay ingress points. Never called on v3 messages (scopedPDU is opaque).
package msg

import (
	"strconv"
)

// snmpTrapOIDDotZeroDotted is snmpTrapOID.0, the varbind that carries the
// trap OID in v2c notifications.
const snmpTrapOIDDotZeroDotted = "1.3.6.1.6.3.1.1.4.1.0"

// TrapOID extracts the notification's trap OID from a raw v1/v2c
// datagram. For v2c traps/informs it reads the snmpTrapOID.0 varbind; for
// v1 traps it derives the RFC 2576 translated form (enterprise.0.specific
// for enterpriseSpecific(6), else snmpTraps.(generic+1)). It reports false
// when the datagram is not a trap/inform, carries no determinable trap OID
// (e.g. no snmpTrapOID.0 varbind), or is malformed.
func TrapOID(dg []byte) (string, bool) {
	_, _, pdu, err := SplitV1V2c(dg)
	if err != nil || len(pdu) == 0 {
		return "", false
	}
	switch pdu[0] {
	case PDUTrap:
		return v1TrapOID(pdu)
	case PDUSNMPv2Trap, PDUInformRequest:
		return v2TrapOID(pdu)
	default:
		return "", false
	}
}

// v1TrapOID derives the RFC 2576 section 3.1 translated trap OID from a
// raw v1 Trap-PDU TLV.
func v1TrapOID(pdu []byte) (string, bool) {
	t, err := SplitV1Trap(pdu)
	if err != nil {
		return "", false
	}
	if t.Generic == 6 {
		ent, err := DecodeOID(t.Enterprise)
		if err != nil {
			return "", false
		}
		return ent + ".0." + strconv.FormatInt(int64(t.Specific), 10), true
	}
	// standard trap: snmpTraps.(generic + 1), same as V1TrapToV2
	return OIDSnmpTrapsDotted + "." + strconv.FormatInt(int64(t.Generic+1), 10), true
}

// v2TrapOID walks the varbinds of a v2c trap/inform PDU TLV looking for
// snmpTrapOID.0 and returns its OID value.
func v2TrapOID(pdu []byte) (string, bool) {
	_, f, err := ParsePDU(pdu)
	if err != nil {
		return "", false
	}
	rest := f.Varbinds
	for len(rest) > 0 {
		vb, err := berTLV(rest)
		if err != nil {
			return "", false
		}
		rest = rest[len(vb):]
		if len(vb) < 2 || vb[0] != 0x30 {
			continue // not a varbind SEQUENCE: skip
		}
		content, err := berContent(vb[1:])
		if err != nil {
			continue
		}
		// varbind content = OID TLV + value TLV
		if len(content) < 2 || content[0] != 0x06 {
			continue
		}
		oidTLV, err := berTLV(content)
		if err != nil {
			continue
		}
		oidVal, err := berContent(oidTLV[1:])
		if err != nil {
			continue
		}
		oidDotted, err := DecodeOID(oidVal)
		if err != nil || oidDotted != snmpTrapOIDDotZeroDotted {
			continue
		}
		// the value TLV follows the OID TLV
		if len(content) == len(oidTLV) {
			return "", false
		}
		valueTLV := content[len(oidTLV):]
		if len(valueTLV) < 2 || valueTLV[0] != 0x06 {
			return "", false
		}
		trapVal, err := berContent(valueTLV[1:])
		if err != nil {
			return "", false
		}
		trapOID, err := DecodeOID(trapVal)
		if err != nil {
			return "", false
		}
		return trapOID, true
	}
	return "", false
}
