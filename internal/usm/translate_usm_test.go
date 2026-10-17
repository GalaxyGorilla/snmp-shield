// translate_usm_test.go (package usm): wire-level regression tests for the
// USM translation path, using gosnmp as an independent marshalling oracle.
package usm

import (
	"encoding/hex"
	"testing"

	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/gosnmp/gosnmp"
)

// TestParseAndDecryptGosnmpAuthPriv feeds a real gosnmp-marshaled authPriv
// request through our v3 parser and AES decryption: proves byte-exact key
// derivation, auth-param location and CFB-128 compatibility with gosnmp.
func TestParseAndDecryptGosnmpAuthPriv(t *testing.T) {
	eid, err := hex.DecodeString("80fca2fb348c3410577081de")
	if err != nil {
		t.Fatal(err)
	}

	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 "proxy",
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: "authpass",
		PrivacyProtocol:          gosnmp.AES,
		PrivacyPassphrase:        "privpass",
		AuthoritativeEngineID:    string(eid),
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  10,
	}
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           gosnmp.AuthPriv,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		PDUType:            gosnmp.GetRequest,
		MsgID:              1234,
		RequestID:          42,
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null, Value: nil},
		},
	}
	// MarshalMsg encrypts with sp.PrivacyKey/sp.PrivacyParameters: both
	// must be set up before marshalling.
	if err := sp.InitSecurityKeys(); err != nil {
		t.Fatal(err)
	}
	if err := sp.InitPacket(pkt); err != nil {
		t.Fatal(err)
	}
	raw, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}

	profiles, err := NewProfiles([]Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
	}}, eid)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := profiles.Lookup("proxy")
	if !ok {
		t.Fatal("user not found")
	}

	m, err := msg.ParseV3(raw)
	if err != nil {
		t.Fatalf("ParseV3: %v", err)
	}
	if !m.IsEncrypted() {
		t.Fatal("scopedPDU should be encrypted")
	}
	if m.USM.Boots != 1 || m.USM.Time != 10 {
		t.Fatalf("bad engine boots/time: %d/%d", m.USM.Boots, m.USM.Time)
	}
	if m.USM.UserName != "proxy" {
		t.Fatalf("bad user %q", m.USM.UserName)
	}

	// auth params offset + digest verification against the gosnmp packet
	off, ok := locateAuthParams(raw, m)
	if !ok {
		t.Fatal("auth params not located")
	}
	if err := Verify(c.p.AuthProtocol, raw, c.authKey, m.USM.AuthParams, off); err != nil {
		t.Fatalf("auth verify: %v", err)
	}

	// decrypt the scopedPDU with the received engine boots/time
	ct, err := scopedCiphertext(m.PDU)
	if err != nil {
		t.Fatalf("scopedCiphertext: %v", err)
	}
	plain, err := decryptScoped(c.p.PrivProtocol, c.privKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, ct)
	if err != nil {
		t.Fatalf("decryptScoped: %v", err)
	}
	if len(plain) == 0 || plain[0] != 0x30 {
		t.Fatalf("decrypted scopedPDU should start with SEQUENCE, got % x", plain[:min(8, len(plain))])
	}
	// the decrypted scopedPDU must contain the client's request-id (42)
	var m2 msg.V3Message
	if err := m2.UnwrapScopedPDU(plain); err != nil {
		t.Fatalf("UnwrapScopedPDU: %v", err)
	}
	if f, ok := pduCommon(m2.PDU); !ok || f.ReqID != 42 {
		t.Fatalf("request-id not preserved: %+v", f)
	}
}

// TestRoundTripEncryptSign verifies our own BuildV3 output (full scopedPDU
// TLV encrypted in place, digest spliced) parses and decrypts again.
func TestRoundTripEncryptSign(t *testing.T) {
	eid, err := hex.DecodeString("801a2b3c4d5e6f708192")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := NewProfiles([]Profile{{
		Name:           "proxy",
		AuthProtocol:   AuthSHA,
		AuthPassphrase: "authpass",
		PrivProtocol:   PrivAES,
		PrivPassphrase: "privpass",
	}}, eid)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := profiles.Lookup("proxy")
	if !ok {
		t.Fatal("user not found")
	}

	pdu := msg.BuildPDU(msg.PDUGetResponse, 777, 0, 0, []byte{0})
	scoped := msg.BuildScoped(eid, []byte{}, pdu)
	boots, etime := uint32(2), uint32(33)
	salt := []byte{0, 0, 0, 0, 0, 0, 0, 9}
	authParams := make([]byte, c.p.AuthProtocol.MacLength())

	encrypt := func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, salt, plain)
	}
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      4242,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   eid,
		Boots:      boots,
		Time:       etime,
		UserName:   "proxy",
		AuthParams: authParams,
		PrivParams: salt,
	}, scoped, encrypt)
	if err != nil {
		t.Fatal(err)
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		t.Fatal(err)
	}

	// parse it back
	m, err := msg.ParseV3(out)
	if err != nil {
		t.Fatalf("ParseV3: %v", err)
	}
	if m.Header.MsgID != 4242 {
		t.Fatalf("msgID changed: %d", m.Header.MsgID)
	}
	if m.USM.Boots != 2 || m.USM.Time != 33 {
		t.Fatalf("boots/time changed: %d/%d", m.USM.Boots, m.USM.Time)
	}

	// verify the digest we spliced
	off, ok := locateAuthParams(out, m)
	if !ok {
		t.Fatal("auth params not located after sign")
	}
	if err := Verify(c.p.AuthProtocol, out, c.authKey, m.USM.AuthParams, off); err != nil {
		t.Fatalf("verify after sign: %v", err)
	}

	// decrypt the scopedPDU
	ct, err := scopedCiphertext(m.PDU)
	if err != nil {
		t.Fatalf("scopedCiphertext: %v", err)
	}
	plain, err := decryptScoped(c.p.PrivProtocol, c.privKey, boots, etime, m.USM.PrivParams, ct)
	if err != nil {
		t.Fatalf("decryptScoped: %v", err)
	}
	var m2 msg.V3Message
	if err := m2.UnwrapScopedPDU(plain); err != nil {
		t.Fatalf("UnwrapScopedPDU: %v", err)
	}
	if f, ok := pduCommon(m2.PDU); !ok || f.ReqID != 777 {
		t.Fatalf("request-id not preserved after round-trip: %+v", f)
	}
}
