package msg

import (
	"testing"
)

// buildVarbind builds one varbind SEQUENCE from raw OID bytes and a
// complete value TLV (tag+content).
func buildVarbind(oidBer []byte, valTLV []byte) []byte {
	vb := AppendTLV(nil, 0x06, oidBer)
	vb = append(vb, valTLV...)
	return AppendTLV(nil, 0x30, vb)
}

// buildV2cTrapMsg assembles a v2c datagram with the given PDU type and
// varbind TLVs.
func buildV2cTrapMsg(pduType uint8, vbs ...[]byte) []byte {
	var list []byte
	for _, vb := range vbs {
		list = append(list, vb...)
	}
	pdu := BuildPDU(pduType, 42, 0, 0, list)
	dg, err := BuildV1V2c(Version2c, []byte("public"), pdu)
	if err != nil {
		panic(err)
	}
	return dg
}

func TestDecodeOIDRoundTrip(t *testing.T) {
	cases := []string{
		"1.3.6.1",
		"1.3.6.1.4.1.8072.999",
		"1.3.6.1.6.3.1.1.4.1.0",
		"1.3.6.1.2.1.1.3.0",
		"2.100.3",
		"1.3.6.1.4.1.4171.20.1",
	}
	for _, dotted := range cases {
		ber, err := EncodeOID(dotted)
		if err != nil {
			t.Fatalf("EncodeOID(%q): %v", dotted, err)
		}
		got, err := DecodeOID(ber)
		if err != nil {
			t.Fatalf("DecodeOID(%q): %v", dotted, err)
		}
		if got != dotted {
			t.Errorf("round trip %q -> %q", dotted, got)
		}
	}
}

func TestDecodeOIDErrors(t *testing.T) {
	if _, err := DecodeOID(nil); err == nil {
		t.Error("DecodeOID(nil) must error")
	}
	// truncated continuation: high bit set on the last octet
	if _, err := DecodeOID([]byte{0x2b, 0x81}); err == nil {
		t.Error("DecodeOID with truncated sub-identifier must error")
	}
}

func TestTrapOIDV2Trap(t *testing.T) {
	trapOID := mustOID("1.3.6.1.4.1.8072.2")
	extra := buildVarbind(mustOID("1.3.6.1.2.1.1.3.0"), AppendInteger(nil, 12345))
	dg := buildV2cTrapMsg(PDUSNMPv2Trap,
		buildVarbind(OIDSnmpTrapOID, AppendTLV(nil, 0x06, trapOID)),
		extra,
	)
	got, ok := TrapOID(dg)
	if !ok {
		t.Fatal("TrapOID failed on v2c trap")
	}
	if got != "1.3.6.1.4.1.8072.2" {
		t.Errorf("TrapOID = %q, want 1.3.6.1.4.1.8072.2", got)
	}
}

func TestTrapOIDInform(t *testing.T) {
	trapOID := mustOID("1.3.6.1.4.1.9999.1")
	dg := buildV2cTrapMsg(PDUInformRequest,
		buildVarbind(OIDSnmpTrapOID, AppendTLV(nil, 0x06, trapOID)),
	)
	got, ok := TrapOID(dg)
	if !ok {
		t.Fatal("TrapOID failed on inform")
	}
	if got != "1.3.6.1.4.1.9999.1" {
		t.Errorf("TrapOID = %q, want 1.3.6.1.4.1.9999.1", got)
	}
}

func TestTrapOIDNoSnmpTrapOIDVarbind(t *testing.T) {
	// A trap without snmpTrapOID.0: no determinable trap OID.
	dg := buildV2cTrapMsg(PDUSNMPv2Trap,
		buildVarbind(mustOID("1.3.6.1.2.1.1.3.0"), AppendInteger(nil, 999)),
	)
	if _, ok := TrapOID(dg); ok {
		t.Error("TrapOID must report false without snmpTrapOID.0 varbind")
	}
}

func TestTrapOIDV1GenericTrap(t *testing.T) {
	// generic coldStart(0) -> snmpTraps.1
	t1 := V1Trap{
		Enterprise: mustOID("1.3.6.1.4.1.9"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    0,
		Specific:   0,
		Timestamp:  12345,
	}
	pdu := BuildV1Trap(t1)
	dg, err := BuildV1V2c(Version1, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := TrapOID(dg)
	if !ok {
		t.Fatal("TrapOID failed on v1 generic trap")
	}
	if got != OIDSnmpTrapsDotted+".1" {
		t.Errorf("TrapOID = %q, want %s.1", got, OIDSnmpTrapsDotted)
	}
}

func TestTrapOIDV1EnterpriseSpecific(t *testing.T) {
	// generic 6, specific 42 -> enterprise.0.42
	t1 := V1Trap{
		Enterprise: mustOID("1.3.6.1.4.1.8072"),
		AgentAddr:  []byte{10, 0, 0, 1},
		Generic:    6,
		Specific:   42,
		Timestamp:  12345,
		Varbinds:   nil,
	}
	pdu := BuildV1Trap(t1)
	dg, err := BuildV1V2c(Version1, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := TrapOID(dg)
	if !ok {
		t.Fatal("TrapOID failed on v1 enterprise-specific trap")
	}
	if got != "1.3.6.1.4.1.8072.0.42" {
		t.Errorf("TrapOID = %q, want 1.3.6.1.4.1.8072.0.42", got)
	}
}

func TestTrapOIDNonTrap(t *testing.T) {
	// A GET request on the trap port: not a notification.
	pdu := BuildPDU(PDUGetRequest, 1, 0, 0, buildVarbind(mustOID("1.3.6.1.2.1.1.1.0"), AppendOctetString(nil, []byte("x"))))
	dg, err := BuildV1V2c(Version2c, []byte("public"), pdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := TrapOID(dg); ok {
		t.Error("TrapOID must report false for a GET")
	}
}

func TestTrapOIDGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x30, 0x03, 0x02, 0x01}, // truncated
		{0x01, 0x02, 0x03},       // not a SEQUENCE
		{0xff, 0xff, 0xff, 0xff}, // garbage
	}
	for i, dg := range cases {
		if _, ok := TrapOID(dg); ok {
			t.Errorf("case %d: TrapOID must report false for garbage", i)
		}
	}
}

func TestTrapOIDV3IsOpaque(t *testing.T) {
	// v3 messages are not v1/v2c: SplitV1V2c rejects them.
	dg := []byte{0x30, 0x06, 0x02, 0x01, 0x03, 0x04, 0x01, 0x61}
	if _, ok := TrapOID(dg); ok {
		t.Error("TrapOID must report false for v3 datagrams")
	}
}
