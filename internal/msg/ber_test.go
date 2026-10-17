package msg

import (
	"bytes"
	"testing"
)

// TestAppendIntegerEncoding pins minimal two's-complement INTEGER encoding.
// A positive value whose top content byte has the high bit set MUST carry a
// leading 0x00 octet: strict parsers (net-snmp) otherwise read the value as
// negative ("Received bad msgMaxSize (18446744073709551615 < 484)" was
// caused by msgMaxSize=65535 encoding as FF FF, i.e. signed -1).
func TestAppendIntegerEncoding(t *testing.T) {
	cases := []struct {
		v    int32
		want []byte // full TLV
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{1, []byte{0x02, 0x01, 0x01}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{255, []byte{0x02, 0x02, 0x00, 0xff}},
		{256, []byte{0x02, 0x02, 0x01, 0x00}},
		{32767, []byte{0x02, 0x02, 0x7f, 0xff}},
		{32768, []byte{0x02, 0x03, 0x00, 0x80, 0x00}},
		{65535, []byte{0x02, 0x03, 0x00, 0xff, 0xff}},
		{2147483647, []byte{0x02, 0x04, 0x7f, 0xff, 0xff, 0xff}},
		{-1, []byte{0x02, 0x01, 0xff}},
		{-128, []byte{0x02, 0x01, 0x80}},
		{-129, []byte{0x02, 0x02, 0xff, 0x7f}},
		{-32768, []byte{0x02, 0x02, 0x80, 0x00}},
		{-2147483648, []byte{0x02, 0x04, 0x80, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := AppendInteger(nil, c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("AppendInteger(%d) = %x, want %x", c.v, got, c.want)
		}
		// round-trip through the BER parser for in-range values
		v, rest, err := berInteger(got)
		if err != nil {
			t.Errorf("berInteger(AppendInteger(%d)) error: %v", c.v, err)
			continue
		}
		if v != c.v {
			t.Errorf("berInteger round-trip: got %d, want %d", v, c.v)
		}
		if len(rest) != 0 {
			t.Errorf("berInteger(%d): %d trailing bytes", c.v, len(rest))
		}
	}
}

// TestAppendUint32Encoding pins the same rule for unsigned fields such as
// engineBoots/engineTime and msgMaxSize.
func TestAppendUint32Encoding(t *testing.T) {
	cases := []struct {
		v    uint32
		want []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{1, []byte{0x02, 0x01, 0x01}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{65535, []byte{0x02, 0x03, 0x00, 0xff, 0xff}},
		{65536, []byte{0x02, 0x03, 0x01, 0x00, 0x00}},
		{2147483648, []byte{0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00}},
		{4294967295, []byte{0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		got := AppendUint32(nil, c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("AppendUint32(%d) = %x, want %x", c.v, got, c.want)
		}
		// round-trip where the value fits int32 positively
		if c.v <= 2147483647 {
			v, _, err := berInteger(got)
			if err != nil {
				t.Errorf("berInteger(AppendUint32(%d)) error: %v", c.v, err)
				continue
			}
			if v != int32(c.v) {
				t.Errorf("berInteger round-trip: got %d, want %d", v, c.v)
			}
		}
	}
}
