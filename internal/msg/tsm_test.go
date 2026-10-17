// tsm_test.go: TSM (RFC 5591) message codec round-trips — secModel 4 with
// an empty securityParameters OCTET STRING.
package msg

import "testing"

func TestBuildParseV3TSM(t *testing.T) {
	pdu := BuildPDU(PDUGetRequest, 4242, 0, 0, []byte{0x30, 0x00})
	scoped := BuildScoped([]byte{0x80, 0x01, 0x02}, []byte{}, pdu)

	out, err := BuildV3(V3Header{
		MsgID:      1234,
		MsgMaxSize: DefaultMsgMaxSize,
		MsgFlags:   MsgFlagReportable,
		SecModel:   SecurityModelTSM,
	}, USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}

	m, err := ParseV3(out)
	if err != nil {
		t.Fatalf("ParseV3: %v", err)
	}
	if m.Header.SecModel != SecurityModelTSM {
		t.Fatalf("SecModel = %d, want %d", m.Header.SecModel, SecurityModelTSM)
	}
	if m.Header.MsgID != 1234 {
		t.Fatalf("MsgID = %d, want 1234", m.Header.MsgID)
	}
	if len(m.SecParams) != 0 {
		t.Fatalf("SecParams not empty: %x", m.SecParams)
	}
	if m.IsEncrypted() {
		t.Fatal("TSM scopedPDU must be plaintext")
	}
	if string(m.ContextEngineID) != string([]byte{0x80, 0x01, 0x02}) {
		t.Fatalf("ContextEngineID = %x", m.ContextEngineID)
	}

	_, f, err := ParsePDU(m.PDU)
	if err != nil {
		t.Fatalf("ParsePDU: %v", err)
	}
	if f.ReqID != 4242 {
		t.Fatalf("ReqID = %d, want 4242", f.ReqID)
	}
}

// TestUnwrapTSMThroughTranslatorShape exercises the exact chain the TSM
// translators use: wrap → ParseV3 → scoped content split → ParsePDU.
func TestUnwrapTSMThroughTranslatorShape(t *testing.T) {
	pdu := BuildPDU(PDUGetResponse, 7, 0, 0, []byte{0x30, 0x00})
	scoped := BuildScoped(nil, []byte{}, pdu)

	out, err := BuildV3(V3Header{
		MsgID:      99,
		MsgMaxSize: DefaultMsgMaxSize,
		MsgFlags:   MsgFlagReportable,
		SecModel:   SecurityModelTSM,
	}, USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}

	m, err := ParseV3(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.SecModel != SecurityModelTSM || m.IsEncrypted() {
		t.Fatal("bad classification")
	}

	// unwrapTSM chain (corrected): ParseV3 already split the plaintext
	// scopedPDU — m.PDU is the raw inner PDU TLV directly.
	if m.PDU[0] != PDUGetResponse {
		t.Fatalf("PDU type = %02x", m.PDU[0])
	}
	_, f, err := ParsePDU(m.PDU)
	if err != nil || f.ReqID != 7 {
		t.Fatalf("ParsePDU = %v err=%v", f, err)
	}
}
