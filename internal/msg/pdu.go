// pdu.go: split/build codecs for SNMPv1/v2c messages, used by the USM
// translate mode. Translation splices the PDU bytes verbatim — the proxy
// never parses varbinds — so the downstream agent sees byte-exact PDUs.
package msg

import (
	"encoding/binary"
	"fmt"
)

// SplitV1V2c splits a raw SNMPv1/v2c datagram into its version, community
// and the PDU TLV (tag octet + length + content) as raw bytes. The PDU
// bytes are preserved verbatim, including the request-id.
func SplitV1V2c(data []byte) (version int, community []byte, pdu []byte, err error) {
	if len(data) < 2 || data[0] != 0x30 {
		return 0, nil, nil, errBadMsg
	}
	content, err := berContent(data[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	ver, rest, err := berInteger(content)
	if err != nil {
		return 0, nil, nil, err
	}
	if int(ver) != Version1 && int(ver) != Version2c {
		return 0, nil, nil, fmt.Errorf("msg: SplitV1V2c on version %d", ver)
	}
	community, rest, err = berOctetString(rest)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(rest) < 2 {
		return 0, nil, nil, errNoPDU
	}
	tag := rest[0]
	if !IsPDUType(tag) {
		return 0, nil, nil, errBadPDU
	}
	pduLen, restAfterLen, err := berLen(rest[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	if len(restAfterLen) < pduLen {
		return 0, nil, nil, errBadPDU
	}
	// PDU TLV = tag + length octets + content. The length octets are the
	// bytes between the tag and restAfterLen.
	nLen := len(rest) - 1 - len(restAfterLen)
	pdu = rest[:1+nLen+pduLen]
	return int(ver), community, pdu, nil
}

// BuildV1V2c assembles a v1/v2c datagram from version, community and the
// raw PDU TLV bytes (as produced by SplitV1V2c).
func BuildV1V2c(version int, community []byte, pdu []byte) ([]byte, error) {
	if version != Version1 && version != Version2c {
		return nil, fmt.Errorf("msg: BuildV1V2c on version %d", version)
	}
	var content []byte
	content = AppendInteger(content, int32(version))
	content = AppendOctetString(content, community)
	content = append(content, pdu...)
	var out []byte
	out = AppendTLV(out, 0x30, content)
	return out, nil
}

// IsPDUType reports whether the tag octet is an SNMP PDU type.
func IsPDUType(t uint8) bool {
	return t >= 0xA0 && t <= 0xA8
}

// --- PDU field access (tag + content level, no varbind parsing) ----------

// PDUFields is the common header of a v1/v2c PDU: request-id, error-status,
// error-index, followed by the varbind sequence.
type PDUFields struct {
	ReqID     int32
	ErrStatus int32
	ErrIndex  int32
	// Varbinds is the CONTENT of the varbind SEQUENCE (individual varbind
	// TLVs, without the SEQUENCE tag/length).
	Varbinds []byte
}

// ParsePDU splits a raw PDU TLV (tag + length + content) into the PDU type
// and its common fields. The varbind list content is returned raw and is
// never parsed.
func ParsePDU(pdu []byte) (pduType uint8, f PDUFields, err error) {
	if len(pdu) < 2 {
		return 0, f, errBadPDU
	}
	pduType = pdu[0]
	if !IsPDUType(pduType) {
		return 0, f, errBadPDU
	}
	body, err := berContent(pdu[1:])
	if err != nil {
		return 0, f, err
	}
	rest := body
	f.ReqID, rest, err = berInteger(rest)
	if err != nil {
		return 0, f, err
	}
	f.ErrStatus, rest, err = berInteger(rest)
	if err != nil {
		return 0, f, err
	}
	f.ErrIndex, rest, err = berInteger(rest)
	if err != nil {
		return 0, f, err
	}
	if len(rest) < 2 || rest[0] != 0x30 {
		return 0, f, errBadPDU
	}
	vbLen, restAfterLen, err := berLen(rest[1:])
	if err != nil {
		return 0, f, err
	}
	if len(restAfterLen) < vbLen {
		return 0, f, errBadPDU
	}
	f.Varbinds = restAfterLen[:vbLen]
	return pduType, f, nil
}

// BuildPDU assembles a raw PDU TLV from a type tag, common fields and the
// raw varbind list CONTENT (as produced by ParsePDU).
func BuildPDU(pduType uint8, reqID, errStatus, errIndex int32, varbinds []byte) []byte {
	var body []byte
	body = AppendInteger(body, reqID)
	body = AppendInteger(body, errStatus)
	body = AppendInteger(body, errIndex)
	body = AppendTLV(body, 0x30, varbinds)
	var pdu []byte
	pdu = append(pdu, pduType)
	pdu = AppendLength(pdu, len(body))
	return append(pdu, body...)
}

// --- v1 trap PDU -----------------------------------------------------------

// V1Trap is the parsed form of an SNMPv1 Trap-PDU (RFC 1157). The
// variable-bindings stay raw (SEQUENCE content).
type V1Trap struct {
	Enterprise []byte // raw BER sub-identifier bytes
	AgentAddr  []byte // 4-byte IPv4
	Generic    int32
	Specific   int32
	Timestamp  uint32 // TimeTicks
	Varbinds   []byte // raw varbind list CONTENT
}

// SplitV1Trap parses a raw v1 Trap-PDU TLV (tag 0xA4).
func SplitV1Trap(pdu []byte) (V1Trap, error) {
	var t V1Trap
	if len(pdu) < 2 || pdu[0] != PDUTrap {
		return t, errBadPDU
	}
	body, err := berContent(pdu[1:])
	if err != nil {
		return t, err
	}
	rest := body
	if t.Enterprise, rest, err = berOctetStringLike(0x06, rest); err != nil {
		return t, err
	}
	// agent-addr: NetworkAddress, APPLICATION 0 (0x40)
	if t.AgentAddr, rest, err = berOctetStringLike(0x40, rest); err != nil {
		return t, err
	}
	if t.Generic, rest, err = berInteger(rest); err != nil {
		return t, err
	}
	if t.Specific, rest, err = berInteger(rest); err != nil {
		return t, err
	}
	// time-stamp: TimeTicks, APPLICATION 3 (0x43)
	tt, rest, err := berOctetStringLike(0x43, rest)
	if err != nil {
		return t, err
	}
	if t.Timestamp, err = berUintFromContent(tt); err != nil {
		return t, err
	}
	// varbinds: SEQUENCE, keep content only
	if len(rest) < 2 || rest[0] != 0x30 {
		return t, errBadPDU
	}
	vbLen, restAfterLen, err := berLen(rest[1:])
	if err != nil {
		return t, err
	}
	if len(restAfterLen) < vbLen {
		return t, errBadPDU
	}
	t.Varbinds = restAfterLen[:vbLen]
	return t, nil
}

// BuildV1Trap assembles a raw v1 Trap-PDU TLV.
func BuildV1Trap(t V1Trap) []byte {
	var body []byte
	body = AppendTLV(body, 0x06, t.Enterprise)
	body = AppendTLV(body, 0x40, t.AgentAddr)
	body = AppendInteger(body, t.Generic)
	body = AppendInteger(body, t.Specific)
	body = appendUintTLV(body, 0x43, t.Timestamp)
	body = AppendTLV(body, 0x30, t.Varbinds)
	var pdu []byte
	pdu = append(pdu, PDUTrap)
	pdu = AppendLength(pdu, len(body))
	return append(pdu, body...)
}

// --- OID constants ----------------------------------------------------------

// Pre-encoded OIDs used by the translation paths.
var (
	OIDSysUpTime          = mustOID("1.3.6.1.2.1.1.3.0")     // sysUpTime.0
	OIDSnmpTrapOID        = mustOID("1.3.6.1.6.3.1.1.4.1.0") // snmpTrapOID.0
	OIDSnmpTrapAddress    = mustOID("1.3.6.1.6.3.18.1.3.0")  // snmpTrapAddress.0
	OIDSnmpTrapCommunity  = mustOID("1.3.6.1.6.3.18.1.4.0")  // snmpTrapCommunity.0
	OIDSnmpTrapEnterprise = mustOID("1.3.6.1.6.3.1.1.5.9")   // snmpTrapEnterprise.0
	OIDSnmpTraps          = mustOID(OIDSnmpTrapsDotted)      // 1.3.6.1.6.3.1.1.5
)

// OIDSnmpTrapsDotted is the snmpTraps prefix; standard trap generic n maps
// to snmpTraps.(n+1) per RFC 2576 3.1.
const OIDSnmpTrapsDotted = "1.3.6.1.6.3.1.1.5"

func mustOID(d string) []byte {
	b, err := EncodeOID(d)
	if err != nil {
		panic(err)
	}
	return b
}

// --- v1 -> v2 trap translation (RFC 2576 section 3.1) ----------------------

// V1TrapToV2 translates an SNMPv1 Trap-PDU into v2 notification parameters
// per RFC 2576 section 3.1: sysUpTime.0 from the timestamp, snmpTrapOID.0
// (enterprise.0.specific for enterpriseSpecific(6), else the standard trap
// for generic 0-5), the original varbinds, and — when proxy is true — the
// snmpTrapAddress.0 / snmpTrapCommunity.0 / snmpTrapEnterprise.0 bindings.
// It returns the raw varbind-list content (like V1Trap.Varbinds): the
// varbind SEQUENCE wrapper is added by BuildPDU, so callers must pass this
// straight into BuildPDU's varbinds argument.
func V1TrapToV2(t V1Trap, community []byte, proxy bool) ([]byte, error) {
	var trapsOID []byte
	if t.Generic == 6 {
		// snmpTrapOID = enterprise.0.specific
		trapsOID = append(append([]byte{}, t.Enterprise...), 0)
		trapsOID = appendSubID(trapsOID, uint64(t.Specific))
	} else {
		// standard trap: snmpTraps + (generic + 1)
		trapsOID = appendSubID(append([]byte{}, OIDSnmpTraps...), uint64(t.Generic+1))
	}

	var vb []byte // varbind TLVs
	// sysUpTime.0 = timestamp (TimeTicks)
	vb = appendVarbind(vb, OIDSysUpTime, 0x43, uint32Bytes(t.Timestamp))
	// snmpTrapOID.0 = trap OID (OID value)
	vb = appendVarbind(vb, OIDSnmpTrapOID, 0x06, trapsOID)
	// original varbinds, verbatim
	vb = append(vb, t.Varbinds...)
	if proxy {
		vb = appendVarbind(vb, OIDSnmpTrapAddress, 0x40, t.AgentAddr)
		vb = appendVarbind(vb, OIDSnmpTrapCommunity, 0x04, community)
		ent := enterpriseOfSnmpTrapOID(t)
		vb = appendVarbind(vb, OIDSnmpTrapEnterprise, 0x06, ent)
	}
	return vb, nil
}

// enterpriseOfSnmpTrapOID reconstructs the v1 enterprise parameter from the
// generated snmpTrapOID: enterprise.0.specific for specific traps, snmpTraps
// prefix otherwise.
func enterpriseOfSnmpTrapOID(t V1Trap) []byte {
	if t.Generic == 6 {
		// trapsOID was enterprise.0.specific: drop last two sub-identifiers.
		return trimSubIDs(t.Enterprise, 0) // enterprise itself
	}
	return append([]byte{}, OIDSnmpTraps...)
}

// trimSubIDs removes the last n sub-identifiers from encoded OID bytes.
func trimSubIDs(oid []byte, n int) []byte {
	if n <= 0 || len(oid) == 0 {
		return append([]byte{}, oid...)
	}
	// collect sub-identifier end offsets
	cuts := make([]int, 0, 8)
	for i := 0; i < len(oid); i++ {
		if oid[i]&0x80 == 0 {
			cuts = append(cuts, i+1)
		}
	}
	if len(cuts) <= n {
		return append([]byte{}, oid...)
	}
	end := cuts[len(cuts)-1-n]
	return append([]byte{}, oid[:end]...)
}

// --- small varbind helpers -------------------------------------------------

// appendVarbind appends one varbind SEQUENCE { OID, value-TLV }.
func appendVarbind(dst, oid []byte, valTag byte, val []byte) []byte {
	vb := AppendTLV(nil, 0x06, oid)
	vb = AppendTLV(vb, valTag, val)
	return AppendTLV(dst, 0x30, vb)
}

func uint32Bytes(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

// appendUintTLV writes an APPLICATION-class unsigned TLV (TimeTicks 0x43,
// etc.) with minimal big-endian content.
func appendUintTLV(dst []byte, tag byte, v uint32) []byte {
	be := uint32Bytes(v)
	i := 0
	for i < len(be)-1 && be[i] == 0 {
		i++
	}
	return AppendTLV(dst, tag, be[i:])
}

// berOctetStringLike parses a TLV with the given tag, treating the content
// as opaque bytes (works for OCTET STRING, OID, IpAddress, TimeTicks...).
func berOctetStringLike(tag byte, buf []byte) ([]byte, []byte, error) {
	if len(buf) == 0 {
		return nil, nil, fmt.Errorf("msg: expected tag 0x%02x, buffer empty", tag)
	}
	if buf[0] != tag {
		return nil, nil, fmt.Errorf("msg: expected tag 0x%02x, got 0x%02x", tag, buf[0])
	}
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < l {
		return nil, nil, errBadPDU
	}
	return rest[:l], rest[l:], nil
}

// berUintFromContent parses an unsigned integer from BER integer content.
func berUintFromContent(content []byte) (uint32, error) {
	if len(content) == 0 || len(content) > 5 {
		return 0, errBadPDU
	}
	var v uint32
	for _, b := range content {
		v = v<<8 | uint32(b)
	}
	return v, nil
}
