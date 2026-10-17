// wire.go: byte-level BER helpers used by the USM translators. These
// complement the msg package with helpers that need to stay local to usm
// (byte-offset walking for auth-param location, int reads).
package usm

import "errors"

var errTrunc = errors.New("usm: truncated BER")

// berLenAt reads length octets at buf (position after a tag).
func berLenAt(buf []byte) (int, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, errTrunc
	}
	b := buf[0]
	if b < 0x80 {
		return int(b), buf[1:], nil
	}
	if b == 0x80 {
		return 0, nil, errTrunc
	}
	n := int(b & 0x7f)
	if n > 4 || len(buf) < 1+n {
		return 0, nil, errTrunc
	}
	l := 0
	for i := 1; i <= n; i++ {
		l = l<<8 | int(buf[i])
	}
	return l, buf[1+n:], nil
}

// berContentOf returns the content of the TLV at buf (position after tag).
func berContentOf(buf []byte) ([]byte, error) {
	l, rest, err := berLenAt(buf)
	if err != nil {
		return nil, err
	}
	if len(rest) < l {
		return nil, errTrunc
	}
	return rest[:l], nil
}

// readInt32 parses an INTEGER TLV at buf.
func readInt32(buf []byte) (int32, []byte, error) {
	if len(buf) < 2 || buf[0] != 0x02 {
		return 0, nil, errTrunc
	}
	l, rest, err := berLenAt(buf[1:])
	if err != nil || l == 0 || l > 4 || len(rest) < l {
		return 0, nil, errTrunc
	}
	var v int32
	if rest[0]&0x80 != 0 {
		v = -1
	}
	for i := 0; i < l; i++ {
		v = v<<8 | int32(rest[i])
	}
	return v, rest[l:], nil
}

// readUint32 parses a non-negative INTEGER TLV at buf.
func readUint32(buf []byte) (uint32, []byte, error) {
	if len(buf) < 2 || buf[0] != 0x02 {
		return 0, nil, errTrunc
	}
	l, rest, err := berLenAt(buf[1:])
	if err != nil || l == 0 || l > 5 || len(rest) < l {
		return 0, nil, errTrunc
	}
	var v uint32
	for i := 0; i < l; i++ {
		v = v<<8 | uint32(rest[i])
	}
	return v, rest[l:], nil
}

// AppendTLVNil appends a TLV (local helper to avoid importing msg here).
func AppendTLVNil(tag byte, content []byte) []byte {
	out := append([]byte{tag}, berLenBytes(len(content))...)
	return append(out, content...)
}

func berLenBytes(l int) []byte {
	switch {
	case l < 0x80:
		return []byte{byte(l)}
	case l <= 0xff:
		return []byte{0x81, byte(l)}
	case l <= 0xffff:
		return []byte{0x82, byte(l >> 8), byte(l)}
	default:
		return []byte{0x83, byte(l >> 16), byte(l >> 8), byte(l)}
	}
}
