package msg

import (
	"bytes"
	"testing"
)

func TestParseVarbindsRoundTrip(t *testing.T) {
	in := []Varbind{
		{OID: "1.3.6.1.2.1.1.1.0", Type: 0x04, Value: []byte("hello")},
		{OID: "1.3.6.1.2.1.1.3.0", Type: 0x43, Value: []byte{0, 0, 0, 7}},
		{OID: "1.3.6.1.4.1.99.1.0", Type: 0x02, Value: []byte{0xFF}}, // -1
		{OID: "1.3.6.1.4.1.99.2.0", Type: 0x81},                      // exception, empty value
	}
	out, err := ParseVarbinds(BuildVarbinds(in))
	if err != nil {
		t.Fatalf("ParseVarbinds: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d varbinds, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].OID != in[i].OID || out[i].Type != in[i].Type {
			t.Fatalf("varbind %d = %+v, want %+v", i, out[i], in[i])
		}
		if !bytes.Equal(out[i].Value, in[i].Value) {
			t.Fatalf("varbind %d value = %x, want %x", i, out[i].Value, in[i].Value)
		}
	}
}

func TestParseVarbindsEmpty(t *testing.T) {
	out, err := ParseVarbinds(nil)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty list produced %d varbinds", len(out))
	}
}

// TestParseVarbindsMalformed pins the fail-closed behaviour the write policy
// depends on: an undecodable varbind list must be an error, never a partial
// list that silently authorizes a SET.
func TestParseVarbindsMalformed(t *testing.T) {
	good := BuildVarbinds([]Varbind{{OID: "1.3.6.1.2.1.1.1.0", Type: 0x04, Value: []byte("x")}})

	cases := map[string][]byte{
		"not a sequence":         {0x04, 0x02, 0x01, 0x02},
		"truncated outer length": {0x30, 0x7f, 0x06, 0x01},
		"missing value":          {0x30, 0x05, 0x06, 0x03, 0x2b, 0x06, 0x01},
		"empty oid":              {0x30, 0x03, 0x06, 0x00},
		"value length past item": {0x30, 0x07, 0x06, 0x03, 0x2b, 0x06, 0x01, 0x04, 0x7f},
	}
	// "trailing bytes": keep the declared length, append a byte inside the
	// outer SEQUENCE by growing the length.
	trailing := append([]byte{}, good...)
	trailing[1]++ // outer SEQUENCE content length +1
	trailing = append(trailing, 0x05)
	cases["trailing bytes in item"] = trailing

	for name, dg := range cases {
		if _, err := ParseVarbinds(dg); err == nil {
			t.Fatalf("%s: accepted a malformed varbind list (%x)", name, dg)
		}
	}
}

// TestBuildVarbindsRejectsBadOID documents that a bad OID is a programming
// error, not a wire case: every caller builds varbinds from decoded or
// config-validated OIDs.
func TestBuildVarbindsRejectsBadOID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("BuildVarbinds accepted an unencodable OID")
		}
	}()
	BuildVarbinds([]Varbind{{OID: "not.an.oid", Type: 0x04}})
}
