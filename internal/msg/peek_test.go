package msg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// berLenPrefix builds a BER length prefix for n content bytes.
func berLenPrefix(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xFF {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n & 0xFF)}
}

// buildV2c builds a minimal v2c SNMP message: SEQUENCE { INTEGER version,
// OCTET STRING community, PDU(tag, INTEGER reqID, ...) }.
func buildV2c(version byte, community string, pduTag byte, reqID int32) []byte {
	ver := []byte{0x02, 0x01, version}
	comm := append([]byte{0x04}, append(berLenPrefix(len(community)), []byte(community)...)...)
	pduBody := []byte{}
	// request-id
	req := make([]byte, 4)
	binary.BigEndian.PutUint32(req, uint32(reqID))
	pduBody = append(pduBody, 0x02, 0x04)
	pduBody = append(pduBody, req...)
	// error-status, error-index (zeros), varbind list (empty SEQUENCE)
	pduBody = append(pduBody, 0x02, 0x01, 0x00)
	pduBody = append(pduBody, 0x02, 0x01, 0x00)
	pduBody = append(pduBody, 0x30, 0x00)
	pdu := append([]byte{pduTag}, append(berLenPrefix(len(pduBody)), pduBody...)...)
	body := append(append(ver, comm...), pdu...)
	out := append([]byte{0x30}, append(berLenPrefix(len(body)), body...)...)
	return out
}

func TestPeekV2cGet(t *testing.T) {
	data := buildV2c(1, "public", PDUGetRequest, 1234)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if info.Version != Version2c {
		t.Fatalf("version=%d want %d", info.Version, Version2c)
	}
	if info.PDUType != PDUGetRequest {
		t.Fatalf("pduType=0x%02x", info.PDUType)
	}
	if info.RequestID != 1234 {
		t.Fatalf("requestID=%d want 1234", info.RequestID)
	}
}

func TestPeekV1Trap(t *testing.T) {
	data := buildV2c(0, "public", PDUTrap, 0)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if info.Version != Version1 || !IsTrap(info.PDUType) {
		t.Fatalf("v1 trap: %+v", info)
	}
}

func TestPeekV2cInform(t *testing.T) {
	data := buildV2c(1, "public", PDUInformRequest, 77)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !IsInform(info.PDUType) {
		t.Fatalf("want inform, got 0x%02x", info.PDUType)
	}
}

func TestPeekV2cGetBulk(t *testing.T) {
	data := buildV2c(1, "public", PDUGetBulkRequest, 5)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !IsGetBulk(info.PDUType) {
		t.Fatalf("want getbulk, got 0x%02x", info.PDUType)
	}
}

func TestPeekV3Opaque(t *testing.T) {
	// A minimal v3-shaped message: version 3 → opaque classification.
	data := buildV2c(3, "", 0xA0, 1)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if info.Version != Version3 {
		t.Fatalf("version=%d want 3", info.Version)
	}
	if info.PDUType != 0 || info.RequestID != 0 {
		t.Fatalf("v3 must be opaque: %+v", info)
	}
}

func TestPeekGarbage(t *testing.T) {
	if _, err := Peek([]byte{0xFF, 0xFF}); err == nil {
		t.Fatal("want error for non-SEQUENCE")
	}
	if _, err := Peek([]byte{0x30}); err == nil {
		t.Fatal("want error for truncated message")
	}
	if _, err := Peek(nil); err == nil {
		t.Fatal("want error for empty datagram")
	}
}

func TestPeekUnsupportedVersion(t *testing.T) {
	data := buildV2c(99, "x", PDUGetRequest, 1)
	if _, err := Peek(data); err == nil {
		t.Fatal("want error for unsupported version")
	}
}

func TestPeekLongFormLength(t *testing.T) {
	// Community long enough to force 0x81 long-form length.
	data := buildV2c(1, string(bytes.Repeat([]byte{'a'}, 200)), PDUGetNextRequest, 9)
	info, err := Peek(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !IsGetNext(info.PDUType) || info.RequestID != 9 {
		t.Fatalf("long-form: %+v", info)
	}
}
