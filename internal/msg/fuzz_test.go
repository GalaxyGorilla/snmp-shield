// fuzz_test.go: Go-native fuzz targets for every wire-facing parser in the
// msg package. These datagrams arrive unauthenticated on clear legs (and,
// pre-authentication, on the tunnel), so the parsers must never panic or
// loop forever on hostile input — only return errors. Run with:
//
//	go test ./internal/msg -run '^$' -fuzz 'Fuzz' -fuzztime 30s
package msg

import (
	"testing"
)

// seedDatagrams are hand-built valid messages used as fuzzing seeds; the
// mutator explores around them (this finds real BER edge cases far faster
// than random bytes alone).
func seedDatagrams() [][]byte {
	seeds := [][]byte{}

	// v2c GET: 1.3.6.1.2.1.1.1.0 -> OCTET "x"
	oid := mustOID("1.3.6.1.2.1.1.1.0")
	vb := appendVarbind(nil, oid, 0x04, []byte("x"))
	vbl := AppendTLV(nil, 0x30, vb)
	pdu := BuildPDU(PDUGetRequest, 1, 0, 0, vbl)
	dg, _ := BuildV1V2c(Version2c, []byte("public"), pdu)
	seeds = append(seeds, dg)

	// v2c trap with snmpTrapOID.0
	trapVB := appendVarbind(nil, OIDSysUpTime, 0x43, []byte{0, 0, 0, 1})
	trapVB = appendVarbind(trapVB, OIDSnmpTrapOID, 0x06, mustOID("1.3.6.1.4.1.99.0.7"))
	trapPDU := BuildPDU(PDUSNMPv2Trap, 0, 0, 0, AppendTLV(nil, 0x30, trapVB))
	trapDG, _ := BuildV1V2c(Version2c, []byte("public"), trapPDU)
	seeds = append(seeds, trapDG)

	// v2c inform
	informPDU := BuildPDU(PDUInformRequest, 5, 0, 0, AppendTLV(nil, 0x30, trapVB))
	informDG, _ := BuildV1V2c(Version2c, []byte("public"), informPDU)
	seeds = append(seeds, informDG)

	// v1 trap (generic 6, enterprise 1.3.6.1.4.1.99)
	v1t := BuildV1Trap(V1Trap{
		Enterprise: mustOID("1.3.6.1.4.1.99"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    6,
		Specific:   7,
		Timestamp:  12345,
		Varbinds:   nil,
	})
	v1dg, _ := BuildV1V2c(Version1, []byte("public"), v1t)
	seeds = append(seeds, v1dg)

	// v1 standard trap (generic 3)
	v1std := BuildV1Trap(V1Trap{
		Enterprise: mustOID("1.3.6.1.4.1.99"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    3,
		Specific:   0,
		Timestamp:  1,
		Varbinds:   nil,
	})
	v1stdDG, _ := BuildV1V2c(Version1, []byte("public"), v1std)
	seeds = append(seeds, v1stdDG)

	// plaintext v3 USM message (discovery-style reportable GET)
	scoped := BuildScoped([]byte{1, 2, 3}, []byte("ctx"), BuildPDU(PDUGetRequest, 9, 0, 0, AppendTLV(nil, 0x30, appendVarbind(nil, oid, 0x05, nil))))
	v3out, _ := BuildV3(V3Header{MsgID: 7, MsgMaxSize: DefaultMsgMaxSize, MsgFlags: MsgFlagReportable, SecModel: SecurityModelUSM}, USMParams{
		EngineID: []byte{0x80, 0x00, 0x1f, 0x88},
		Boots:    1,
		Time:     2,
		UserName: "proxy",
	}, scoped, nil)
	seeds = append(seeds, v3out)

	// plaintext v3 TSM message (empty securityParameters per RFC 5591)
	tsmOut, _ := BuildV3(V3Header{MsgID: 8, MsgMaxSize: DefaultMsgMaxSize, MsgFlags: 0, SecModel: SecurityModelTSM}, USMParams{}, scoped, nil)
	seeds = append(seeds, tsmOut)

	// encrypted v3 message body (ciphertext TLV inside an OCTET STRING
	// scopedPDU position) — UnwrapScopedPDU input shape
	encBody := EncryptAES([]byte{0x30, 0x0a, 0x04, 0x01, 0x01, 0x04, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x01}, make([]byte, 16), []byte{0, 0, 0, 1}, []byte{0, 0, 0, 2}, make([]byte, 8))
	seeds = append(seeds, encBody)

	// raw OID bytes used by DecodeOID
	seeds = append(seeds, mustOID("1.3.6.1.6.3.1.1.4.1.0"))

	return seeds
}

// FuzzPeek: the leg router sees every datagram first.
func FuzzPeek(f *testing.F) {
	for _, s := range seedDatagrams() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Peek(data)
	})
}

// FuzzSplitV1V2c: the v1/v2c split codec feeding translation and TrapOID.
func FuzzSplitV1V2c(f *testing.F) {
	for _, s := range seedDatagrams() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		version, community, pdu, err := SplitV1V2c(data)
		if err != nil {
			return
		}
		// On success the invariants must hold: known version, valid
		// PDU TLV with the declared content fully inside the datagram.
		if version != Version1 && version != Version2c {
			t.Fatalf("SplitV1V2c succeeded with version %d", version)
		}
		if len(pdu) < 2 || !IsPDUType(pdu[0]) {
			t.Fatalf("SplitV1V2c succeeded with bad PDU TLV %x", pdu)
		}
		if !containsSlice(data, pdu) {
			t.Fatalf("SplitV1V2c returned PDU outside the datagram")
		}
		if community == nil {
			t.Fatalf("SplitV1V2c succeeded with nil community")
		}
	})
}

// FuzzParsePDU: common-field extraction over arbitrary PDU TLVs.
func FuzzParsePDU(f *testing.F) {
	pdu := BuildPDU(PDUGetResponse, 42, 0, 0, AppendTLV(nil, 0x30, appendVarbind(nil, mustOID("1.3.6.1"), 0x04, []byte("v"))))
	f.Add(pdu)
	f.Add(BuildPDU(PDUTrap, 0, 0, 0, nil))
	f.Add(BuildPDU(PDUReport, -1, -1, -1, nil))
	f.Add(BuildPDU(PDUGetBulkRequest, 1<<30, 5, 5, nil))
	f.Fuzz(func(t *testing.T, pdu []byte) {
		typ, fields, err := ParsePDU(pdu)
		if err != nil {
			return
		}
		if !IsPDUType(typ) {
			t.Fatalf("ParsePDU succeeded with non-PDU type %#x", typ)
		}
		// varbinds must lie inside the PDU TLV
		if !containsSlice(pdu, fields.Varbinds) {
			t.Fatalf("ParsePDU varbinds outside the PDU TLV")
		}
	})
}

// FuzzSplitV1Trap: the v1 trap layout parser (never feed it ParsePDU).
func FuzzSplitV1Trap(f *testing.F) {
	f.Add(BuildV1Trap(V1Trap{Enterprise: mustOID("1.3.6.1.4.1.99"), AgentAddr: []byte{1, 2, 3, 4}, Generic: 6, Specific: 7, Timestamp: 99, Varbinds: nil}))
	f.Add(BuildV1Trap(V1Trap{Enterprise: nil, AgentAddr: nil, Generic: 0, Specific: 0, Timestamp: 0, Varbinds: []byte{0x30, 0x00}}))
	f.Fuzz(func(t *testing.T, pdu []byte) {
		trap, err := SplitV1Trap(pdu)
		if err != nil {
			return
		}
		// On success: generic/specific parse, varbinds inside the TLV.
		if !containsSlice(pdu, trap.Varbinds) {
			t.Fatalf("SplitV1Trap varbinds outside the PDU TLV")
		}
		// Round-trip must rebuild a byte-exact TLV (both are built by
		// our own builder from the same parsed fields).
		rebuilt := BuildV1Trap(trap)
		if !bytesEqual(rebuilt, pdu) {
			// Not an invariant for foreign encodings (non-minimal
			// lengths, non-minimal integers); only check structural
			// re-parseability.
			if _, err := SplitV1Trap(rebuilt); err != nil {
				t.Fatalf("rebuilt v1 trap does not re-parse: %v", err)
			}
		}
	})
}

// FuzzParseV3: full v3 message decomposition (USM + TSM paths).
func FuzzParseV3(f *testing.F) {
	for _, s := range seedDatagrams() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseV3(data)
		if err != nil {
			return
		}
		// Invariants on success.
		if m.Header.SecModel != SecurityModelUSM && m.Header.SecModel != SecurityModelTSM {
			// other sec models parse; nothing to assert
			return
		}
		if m.Header.SecModel == SecurityModelTSM && len(m.SecParams) != 0 {
			t.Fatalf("TSM message parsed with non-empty secParams")
		}
		if len(m.Raw) == 0 {
			t.Fatalf("ParseV3 success with empty Raw")
		}
	})
}

// FuzzUnwrapScopedPDU: decryption input handling — the ciphertext TLV
// content is attacker-controlled when a key is known.
func FuzzUnwrapScopedPDU(f *testing.F) {
	scoped := BuildScoped([]byte{1, 2, 3}, []byte("ctx"), BuildPDU(PDUGetRequest, 1, 0, 0, nil))
	f.Add(AppendTLV(nil, 0x30, scoped))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x04, 0x02, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, plain []byte) {
		m := &V3Message{}
		_ = m.UnwrapScopedPDU(plain)
	})
}

// FuzzTrapOID: the notification filter's classifier.
func FuzzTrapOID(f *testing.F) {
	for _, s := range seedDatagrams() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = TrapOID(data)
	})
}

// FuzzDecodeOID: raw sub-identifier bytes to dotted string — hostile
// varbind OIDs land here.
func FuzzDecodeOID(f *testing.F) {
	f.Add(mustOID("1.3.6.1.6.3.1.1.4.1.0"))
	f.Add([]byte{0x2b, 0x06, 0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x7f})
	f.Add([]byte{0x80})
	f.Add([]byte{0x8f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	f.Fuzz(func(t *testing.T, ber []byte) {
		dotted, err := DecodeOID(ber)
		if err != nil {
			return
		}
		// Round-trip: encoding the decoded string must reproduce the
		// original bytes for canonical encodings.
		re, err2 := EncodeOID(dotted)
		if err2 != nil {
			t.Fatalf("DecodeOID(%x) = %q but EncodeOID fails: %v", ber, dotted, err2)
		}
		if !bytesEqual(re, canonicalOID(ber)) {
			// Non-canonical (overlong/zero-padded) encodings may
			// legitimately differ; re-decode must still agree.
			d2, err3 := DecodeOID(re)
			if err3 != nil || d2 != dotted {
				t.Fatalf("DecodeOID round-trip mismatch: %q vs %q", d2, dotted)
			}
		}
	})
}

// containsSlice reports whether sub appears anywhere in data (same backing
// rules as the parsers' rest[:l] slices).
func containsSlice(data, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(data); i++ {
		if bytesEqual(data[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// canonicalOID strips overlong/zero-padded sub-identifier encodings so
// round-trip comparisons only apply to canonical forms.
func canonicalOID(ber []byte) []byte {
	out := make([]byte, 0, len(ber))
	var cur []byte
	flush := func() {
		if len(cur) == 0 {
			return
		}
		// strip leading 0x80 octets (overlong encodings of the same value)
		i := 0
		for i < len(cur)-1 && cur[i] == 0x80 {
			i++
		}
		out = append(out, cur[i:]...)
		cur = nil
	}
	for _, b := range ber {
		cur = append(cur, b)
		if b&0x80 == 0 {
			flush()
		}
	}
	flush()
	return out
}

// FuzzParseVarbinds covers the single varbind decoder shared by the write
// policy and every relaying mode. A panic here happens pre-authorization on
// a SET, and a silently truncated list would authorize the wrong objects, so
// the target pins both: errors only, and full round-trip fidelity.
func FuzzParseVarbinds(f *testing.F) {
	seeds := seedDatagrams()
	for _, dg := range seeds {
		// Use the PDU body's varbind content as the seed where available;
		// the raw datagram is a useful malformed seed either way.
		f.Add(dg)
	}
	f.Add(BuildVarbinds(nil))
	f.Add(BuildVarbinds([]Varbind{
		{OID: "1.3.6.1.2.1.1.1.0", Type: 0x04, Value: []byte("x")},
		{OID: "1.3.6.1.6.3.1.1.5.1", Type: 0x06, Value: mustOID("1.3.6.1.4.1.99")},
	}))

	f.Fuzz(func(t *testing.T, content []byte) {
		vbs, err := ParseVarbinds(content)
		if err != nil {
			return
		}
		// Whatever parses must re-encode to an equivalent list: same
		// count, same OIDs, same tags and values, and the re-encoded
		// content must parse back to the same thing (stability).
		rebuilt := BuildVarbinds(vbs)
		again, err := ParseVarbinds(rebuilt)
		if err != nil {
			t.Fatalf("re-encoded varbind list does not parse: %v (%x)", err, rebuilt)
		}
		if len(again) != len(vbs) {
			t.Fatalf("varbind count changed across round trip: %d -> %d", len(vbs), len(again))
		}
		for i := range vbs {
			if again[i].OID != vbs[i].OID || again[i].Type != vbs[i].Type ||
				!bytesEqual(again[i].Value, vbs[i].Value) {
				t.Fatalf("varbind %d changed across round trip: %+v -> %+v", i, vbs[i], again[i])
			}
		}
	})
}
