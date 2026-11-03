package msg

import "testing"

// TestDiscoveryRequestHasEmptyVarbindList pins RFC 3414 §4: the discovery
// probe is a GetRequest with an EMPTY variable-bindings field. The original
// code passed []byte{0}, which encodes a one-byte varbind list (30 01 00) —
// not an empty one (30 00). net-snmp tolerates it; pysnmp rejects the
// datagram, so the manager-gateway/passthrough discovery timed out against
// the second independent agent while every net-snmp test stayed green.
func TestDiscoveryRequestHasEmptyVarbindList(t *testing.T) {
	pdu := BuildPDU(PDUGetRequest, 1, 0, 0, nil)
	typ, fields, err := ParsePDU(pdu)
	if err != nil {
		t.Fatalf("ParsePDU: %v", err)
	}
	if typ != PDUGetRequest {
		t.Fatalf("pdu type = %#x, want GetRequest", typ)
	}
	if len(fields.Varbinds) != 0 {
		t.Fatalf("discovery varbind list content = %x, want empty", fields.Varbinds)
	}
	// The whole PDU must end with an empty SEQUENCE (tag 0x30, length 0),
	// not a SEQUENCE containing a zero byte.
	if got := pdu[len(pdu)-2:]; got[0] != 0x30 || got[1] != 0x00 {
		t.Fatalf("discovery varbind list = %x, want 30 00", got)
	}
}
