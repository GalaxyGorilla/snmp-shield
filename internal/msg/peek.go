// Package msg provides SNMP message build/parse helpers. The peek
// functions classify raw datagrams without fully parsing them: enough to
// route v1/v2c/v3 requests, responses, traps and informs on the clear
// legs.
package msg

import (
	"errors"
	"fmt"
)

// SNMP version numbers as they appear in the message version field.
const (
	Version1  = 0
	Version2c = 1
	Version3  = 3
)

// PDU types (tag octet values in the ASN.1 APPLICATION class).
const (
	PDUGetRequest     uint8 = 0xA0
	PDUGetNextRequest uint8 = 0xA1
	PDUGetResponse    uint8 = 0xA2
	PDUSetRequest     uint8 = 0xA3
	PDUTrap           uint8 = 0xA4 // v1 trap
	PDUGetBulkRequest uint8 = 0xA5
	PDUInformRequest  uint8 = 0xA6
	PDUSNMPv2Trap     uint8 = 0xA7
	PDUReport         uint8 = 0xA8
)

// PDU type classification helpers.
func IsGet(t uint8) bool         { return t == PDUGetRequest }
func IsGetNext(t uint8) bool     { return t == PDUGetNextRequest }
func IsGetResponse(t uint8) bool { return t == PDUGetResponse }
func IsSet(t uint8) bool         { return t == PDUSetRequest }
func IsGetBulk(t uint8) bool     { return t == PDUGetBulkRequest }
func IsTrap(t uint8) bool        { return t == PDUTrap || t == PDUSNMPv2Trap }
func IsInform(t uint8) bool      { return t == PDUInformRequest }

// Info is the classification result of a raw SNMP datagram.
type Info struct {
	Version   int
	PDUType   uint8
	RequestID int32
}

// Peek parses just enough BER to classify a datagram: version, PDU type
// and request-id. For v3, the message is opaque (scopedPDU is encrypted)
// so RequestID is 0 and the caller must match responses by locality.
func Peek(data []byte) (Info, error) {
	if len(data) < 2 {
		return Info{}, errors.New("msg: datagram too short")
	}
	if data[0] != 0x30 {
		return Info{}, fmt.Errorf("msg: not an SNMP message (tag 0x%02x)", data[0])
	}

	// Outer SEQUENCE: read its length; content is version + rest.
	content, err := berContent(data[1:])
	if err != nil {
		return Info{}, err
	}

	ver, rest, err := berInteger(content)
	if err != nil {
		return Info{}, err
	}

	switch int(ver) {
	case Version1, Version2c:
		// community string OCTET STRING
		_, rest, err := berOctetString(rest)
		if err != nil {
			return Info{}, err
		}
		// PDU: [APPLICATION n] IMPLICIT PDU; first octet is the tag,
		// then length, then content starting with the request-id.
		if len(rest) < 2 {
			return Info{}, errors.New("msg: no PDU after community")
		}
		t := rest[0]
		pduBody, err := berContent(rest[1:])
		if err != nil {
			// Not fatal: classify by type only.
			return Info{Version: int(ver), PDUType: t, RequestID: 0}, nil
		}
		reqID, _, err := berInteger(pduBody)
		if err != nil {
			// Not fatal: classify by type only.
			return Info{Version: int(ver), PDUType: t, RequestID: 0}, nil
		}
		return Info{Version: int(ver), PDUType: t, RequestID: reqID}, nil

	case Version3:
		// RFC 3412: the scopedPDU is inside msgSecurityParameters+scopedPDU
		// and typically encrypted: opaque to passthrough. Classify by
		// version only; responses are matched by locality.
		return Info{Version: int(ver), PDUType: 0, RequestID: 0}, nil

	default:
		return Info{}, fmt.Errorf("msg: unsupported version %d", ver)
	}
}

// --- minimal BER helpers -------------------------------------------------

// berLen reads the length octets at the start of buf (after the tag).
// It returns the length and the rest.
func berLen(buf []byte) (int, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, errors.New("msg: truncated length")
	}
	b := buf[0]
	if b < 0x80 {
		return int(b), buf[1:], nil
	}
	if b == 0x80 {
		return 0, nil, errors.New("msg: indefinite length not supported")
	}
	n := int(b & 0x7f)
	if n > 4 || len(buf) < 1+n {
		return 0, nil, errors.New("msg: bad long-form length")
	}
	l := 0
	for i := 1; i <= n; i++ {
		l = l<<8 | int(buf[i])
	}
	return l, buf[1+n:], nil
}

// berContent reads the length prefix at buf (position after the tag) and
// returns the TLV content bytes.
func berContent(buf []byte) ([]byte, error) {
	l, rest, err := berLen(buf)
	if err != nil {
		return nil, err
	}
	if len(rest) < l {
		return nil, errors.New("msg: truncated TLV")
	}
	return rest[:l], nil
}

// berTLV returns the complete TLV (tag + length + content) at buf.
func berTLV(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, errors.New("msg: truncated TLV")
	}
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return nil, err
	}
	if len(rest) < l {
		return nil, errors.New("msg: truncated TLV")
	}
	hdrLen := 1 + (len(buf) - 1 - len(rest))
	return buf[:hdrLen+l], nil
}

// berInteger parses an INTEGER TLV, returning its int32 value and rest.
func berInteger(buf []byte) (int32, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, errors.New("msg: truncated integer")
	}
	if buf[0] != 0x02 {
		return 0, nil, fmt.Errorf("msg: expected INTEGER, got tag 0x%02x", buf[0])
	}
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return 0, nil, err
	}
	if len(rest) < l || l == 0 || l > 4 {
		return 0, nil, errors.New("msg: bad INTEGER length")
	}
	var v int32
	if rest[0]&0x80 != 0 {
		v = -1 // sign-extend
	}
	for i := 0; i < l; i++ {
		v = v<<8 | int32(rest[i])
	}
	return v, rest[l:], nil
}

// berOctetString parses an OCTET STRING TLV, returning its bytes and rest.
func berOctetString(buf []byte) ([]byte, []byte, error) {
	if len(buf) == 0 {
		return nil, nil, errors.New("msg: truncated octet string")
	}
	if buf[0] != 0x04 {
		return nil, nil, fmt.Errorf("msg: expected OCTET STRING, got tag 0x%02x", buf[0])
	}
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < l {
		return nil, nil, errors.New("msg: truncated octet string")
	}
	return rest[:l], rest[l:], nil
}
