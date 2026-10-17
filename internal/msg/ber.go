// ber.go: BER/DER encoding helpers complementing the parsers in peek.go.
// These build TLV elements for the v1/v2c <-> v3 translation codec.
package msg

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// AppendLength appends a BER length octet string for l, using long form
// when l >= 128 (short form otherwise).
func AppendLength(dst []byte, l int) []byte {
	switch {
	case l < 0x80:
		return append(dst, byte(l))
	case l <= 0xff:
		return append(dst, 0x81, byte(l))
	case l <= 0xffff:
		return append(dst, 0x82, byte(l>>8), byte(l))
	default:
		return append(dst, 0x83, byte(l>>16), byte(l>>8), byte(l))
	}
}

// AppendTLV appends a complete TLV with the given tag and content.
func AppendTLV(dst []byte, tag byte, content []byte) []byte {
	dst = append(dst, tag)
	dst = AppendLength(dst, len(content))
	return append(dst, content...)
}

// AppendInteger appends an INTEGER TLV. Zero encodes as one 0x00 octet;
// values are encoded in minimal two's-complement form: a leading 0x00
// octet is required when the top content byte has the high bit set
// (otherwise strict parsers such as net-snmp read the value as negative).
func AppendInteger(dst []byte, v int32) []byte {
	var content []byte
	switch {
	case v == 0:
		content = []byte{0}
	case v > 0:
		be := binary.BigEndian.AppendUint32(nil, uint32(v))
		// strip leading zero octets (keep at least one)
		i := 0
		for i < len(be)-1 && be[i] == 0 {
			i++
		}
		content = be[i:]
		// two's complement: positive value whose top bit is set needs a
		// leading 0x00 so the encoding stays positive
		if content[0]&0x80 != 0 {
			content = append([]byte{0}, content...)
		}
	default: // v < 0
		be := binary.BigEndian.AppendUint32(nil, uint32(v))
		i := 0
		for i < len(be)-1 && be[i] == 0xff && be[i+1]&0x80 != 0 {
			i++
		}
		content = be[i:]
	}
	return AppendTLV(dst, 0x02, content)
}

// AppendUint32 appends a non-negative INTEGER TLV (same encoding as
// AppendInteger for values >= 0; separate name for readability at call
// sites carrying unsigned fields such as boots/time).
func AppendUint32(dst []byte, v uint32) []byte {
	be := binary.BigEndian.AppendUint32(nil, v)
	i := 0
	for i < len(be)-1 && be[i] == 0 {
		i++
	}
	content := be[i:]
	// two's complement: top bit set needs a leading 0x00 so the encoding
	// stays positive for strict parsers
	if content[0]&0x80 != 0 {
		content = append([]byte{0}, content...)
	}
	return AppendTLV(dst, 0x02, content)
}

// AppendOctetString appends an OCTET STRING TLV.
func AppendOctetString(dst []byte, content []byte) []byte {
	return AppendTLV(dst, 0x04, content)
}

// AppendOID appends an OBJECT IDENTIFIER TLV. oidBytes are the raw
// sub-identifier bytes including the encoded first two arcs (see EncodeOID).
func AppendOIDTLV(dst []byte, oidBytes []byte) []byte {
	return AppendTLV(dst, 0x06, oidBytes)
}

// EncodeOID converts a dotted OID string to BER sub-identifier bytes
// (base-128, high bit set on all but the last octet), including the
// combined first arc (40*x+y) encoding.
func EncodeOID(dotted string) ([]byte, error) {
	parts := splitDotted(dotted)
	if len(parts) < 2 {
		return nil, errShortOID
	}
	arcs := make([]uint64, 0, len(parts))
	for _, p := range parts {
		v, err := parseUint(p)
		if err != nil {
			return nil, errBadOID
		}
		arcs = append(arcs, v)
	}
	var out []byte
	out = appendSubID(out, uint64(arcs[0])*40+arcs[1])
	for _, a := range arcs[2:] {
		out = appendSubID(out, a)
	}
	return out, nil
}

func appendSubID(dst []byte, v uint64) []byte {
	if v < 0x80 {
		return append(dst, byte(v))
	}
	var tmp [10]byte
	n := len(tmp)
	for v > 0 {
		n--
		tmp[n] = byte(v&0x7f) | 0x80
		v >>= 7
	}
	tmp[len(tmp)-1] &= 0x7f // clear continuation on last octet
	return append(dst, tmp[n:]...)
}

// splitDotted splits a dotted string on '.'.
func splitDotted(s string) []string {
	var parts []string
	for len(s) > 0 {
		i := -1
		for j := 0; j < len(s); j++ {
			if s[j] == '.' {
				i = j
				break
			}
		}
		if i < 0 {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:i])
		s = s[i+1:]
	}
	return parts
}

// parseUint parses a non-negative decimal uint64.
func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, errBadOID
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errBadOID
		}
		v = v*10 + uint64(s[i]-'0')
	}
	return v, nil
}

// NextTLV splits the first TLV off buf and returns its tag, content and
// the remaining bytes. Used to walk varbind sequences and similar TLV
// streams.
func NextTLV(buf []byte) (tag byte, content, rest []byte, err error) {
	if len(buf) < 2 {
		return 0, nil, nil, errShortTLV
	}
	tag = buf[0]
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	if len(rest) < l {
		return 0, nil, nil, errBadTLV
	}
	return tag, rest[:l], rest[l:], nil
}

// DecodeOID converts raw BER sub-identifier bytes (as produced by
// EncodeOID, or extracted from a varbind) to a dotted OID string. The
// combined first arc (40*x+y) is split back into x.y.
func DecodeOID(ber []byte) (string, error) {
	if len(ber) == 0 {
		return "", errShortOID
	}
	arcs := make([]uint64, 0, len(ber)+1)
	var v uint64
	for i, b := range ber {
		v = v<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			arcs = append(arcs, v)
			v = 0
		} else if i == len(ber)-1 {
			// truncated sub-identifier: continuation with no terminator
			return "", errBadOID
		}
	}
	if len(arcs) < 1 {
		return "", errShortOID
	}
	// split the combined first arc back into x.y
	var head []uint64
	switch first := arcs[0]; {
	case first < 40:
		head = []uint64{0, first}
	case first < 80:
		head = []uint64{1, first - 40}
	default:
		head = []uint64{2, first - 80}
	}
	arcs = append(head, arcs[1:]...)
	var sb strings.Builder
	for i, a := range arcs {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.FormatUint(a, 10))
	}
	return sb.String(), nil
}
