// v3.go: SNMPv3 message codec for the USM translate mode. Builds and
// parses RFC 3412 v3 messages with USM (RFC 3414) security parameters,
// byte-compatible with gosnmp and net-snmp. The scopedPDU PDU bytes are
// spliced verbatim, never parsed.
package msg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// v3 message constants (RFC 3412 / RFC 3414).
const (
	SecurityModelUSM = 3 // snmpV3SecurityModel USM
	SecurityModelTSM = 4 // snmpV3SecurityModel TSM (RFC 5591)

	MsgFlagNoAuthNoPriv = 0x00
	MsgFlagAuth         = 0x01 // authentication used
	MsgFlagPriv         = 0x02 // encryption used
	MsgFlagReportable   = 0x04 // report PDU possible

	DefaultMsgMaxSize = 65535
)

// V3Header is the parsed msgHeader (RFC 3412 6.5).
type V3Header struct {
	MsgID      int32
	MsgMaxSize int32
	MsgFlags   byte
	SecModel   int32
}

// USMParams is the parsed USM security parameters (RFC 3414 2.4).
type USMParams struct {
	EngineID   []byte
	Boots      uint32
	Time       uint32
	UserName   string
	AuthParams []byte // 12/16/24/32/48 bytes when authenticated
	PrivParams []byte // 8-byte salt when encrypted
}

// V3Message is a fully decomposed (but not decrypted) SNMPv3 message.
type V3Message struct {
	Header V3Header
	USM    USMParams
	// ScopedPDU content: contextEngineID, contextName and the raw PDU TLV.
	ContextEngineID []byte
	ContextName     []byte
	PDU             []byte // raw PDU TLV (tag + length + content)
	// Raw message bytes and the offset of the security parameters OCTET
	// STRING content (for zeroing auth params during verification).
	Raw       []byte
	SecParams []byte // raw USM SEQUENCE TLV (tag + length + content)
}

// ParseV3 decomposes an SNMPv3 message into header, USM params, and
// scopedPDU fields. It does not decrypt: the scopedPDU is returned as the
// raw OCTET STRING TLV when encrypted, or split into context+PDU when
// plaintext. Decryption is the caller's job (USM layer) via
// UnwrapScopedPDU.
func ParseV3(data []byte) (*V3Message, error) {
	if len(data) < 2 || data[0] != 0x30 {
		return nil, errBadV3
	}
	content, err := berContent(data[1:])
	if err != nil {
		return nil, err
	}
	m := &V3Message{Raw: data}

	// INTEGER version (== 3)
	ver, rest, err := berInteger(content)
	if err != nil {
		return nil, err
	}
	if int(ver) != Version3 {
		return nil, fmt.Errorf("msg: ParseV3 on version %d", ver)
	}

	// msgHeader SEQUENCE
	if len(rest) < 2 || rest[0] != 0x30 {
		return nil, errBadV3
	}
	hdrContent, err := berContent(rest[1:])
	if err != nil {
		return nil, err
	}
	// advance rest past the msgHeader TLV (tag + length octets + content)
	hdrTLVLen := 1 + encLenLen(rest[1:]) + len(hdrContent)
	if hdrTLVLen > len(rest) {
		return nil, errBadV3
	}
	rest = rest[hdrTLVLen:]
	h := hdrContent
	if m.Header.MsgID, h, err = berInteger(h); err != nil {
		return nil, err
	}
	if m.Header.MsgMaxSize, h, err = berInteger(h); err != nil {
		return nil, err
	}
	if len(h) < 2 || h[0] != 0x04 {
		return nil, errBadV3
	}
	if m.Header.MsgFlags, h, err = berSingleOctet(h); err != nil {
		return nil, err
	}
	if m.Header.SecModel, _, err = berInteger(h); err != nil {
		return nil, err
	}

	// msgSecurityParameters OCTET STRING
	if len(rest) < 2 || rest[0] != 0x04 {
		return nil, errBadV3
	}
	m.SecParams, rest, err = berOctetString(rest)
	if err != nil {
		return nil, err
	}
	if m.Header.SecModel == SecurityModelTSM {
		// RFC 5591: TSM messages carry an empty securityParameters
		// OCTET STRING; nothing to parse.
		if len(m.SecParams) != 0 {
			return nil, errBadV3
		}
	} else if m.USM, err = ParseUSM(m.SecParams); err != nil {
		return nil, err
	}

	// scopedPDU: plaintext SEQUENCE or ciphertext OCTET STRING
	if len(rest) < 2 {
		return nil, errBadV3
	}
	switch rest[0] {
	case 0x30:
		// plaintext scopedPDU SEQUENCE: enter its content (ctxEngineID,
		// ctxName, PDU)
		sc, err := berContent(rest[1:])
		if err != nil {
			return nil, err
		}
		ce, rest2, err := berOctetString(sc)
		if err != nil {
			return nil, err
		}
		m.ContextEngineID = ce
		if m.ContextName, rest2, err = berOctetString(rest2); err != nil {
			return nil, err
		}
		pduTLV, err := berTLV(rest2)
		if err != nil {
			return nil, err
		}
		m.PDU = pduTLV
	case 0x04:
		// encrypted: PDU holds the raw OCTET STRING TLV; caller decrypts
		// the content with UnwrapScopedPDU after keying up.
		m.PDU = rest
	default:
		return nil, errBadV3
	}
	return m, nil
}

// encLenLen returns the number of length octets at buf (after the tag).
func encLenLen(buf []byte) int {
	if len(buf) < 2 {
		return 0
	}
	b := buf[1]
	if b < 0x80 {
		return 1
	}
	return int(b & 0x7f)
}

// IsEncrypted reports whether the scopedPDU arrived encrypted.
func (m *V3Message) IsEncrypted() bool {
	return len(m.PDU) >= 1 && m.PDU[0] == 0x04
}

// UnwrapScopedPDU decrypts the encrypted scopedPDU TLV (as left in PDU by
// ParseV3) with the given priv key and params, then splits context + PDU.
// plain is the ciphertext content; the IV is built from boots/time/salt.
func (m *V3Message) UnwrapScopedPDU(plain []byte) error {
	rest := plain
	if len(rest) < 2 || rest[0] != 0x30 {
		return errBadV3
	}
	// enter the outer SEQUENCE: plain is the full TLV, content follows
	// the tag/length octets.
	content, err := berContent(rest[1:])
	if err != nil {
		return err
	}
	ce, rest2, err := berOctetString(content)
	if err != nil {
		return err
	}
	m.ContextEngineID = ce
	if m.ContextName, rest2, err = berOctetString(rest2); err != nil {
		return err
	}
	if len(rest2) < 2 {
		return errBadV3
	}
	pduLen, ra, err := berLen(rest2[1:])
	if err != nil {
		return err
	}
	if len(ra) < pduLen {
		return errBadV3
	}
	nLen := len(rest2) - 1 - len(ra)
	m.PDU = rest2[:1+nLen+pduLen]
	return nil
}

// ParseScopedPDU splits a plaintext scopedPDU SEQUENCE content into
// context engine ID/name and raw PDU TLV.
func ParseScopedPDU(content []byte) (ctxEngineID, ctxName, pdu []byte, err error) {
	rest := content
	if ctxEngineID, rest, err = berOctetString(rest); err != nil {
		return nil, nil, nil, err
	}
	if ctxName, rest, err = berOctetString(rest); err != nil {
		return nil, nil, nil, err
	}
	if len(rest) < 2 {
		return nil, nil, nil, errBadV3
	}
	pduLen, ra, err := berLen(rest[1:])
	if err != nil {
		return nil, nil, nil, err
	}
	if len(ra) < pduLen {
		return nil, nil, nil, errBadV3
	}
	nLen := len(rest) - 1 - len(ra)
	pdu = rest[:1+nLen+pduLen]
	return ctxEngineID, ctxName, pdu, nil
}

// ParseUSM parses USM security parameters. content is the OCTET STRING
// content (the USM SEQUENCE TLV); the SEQUENCE is entered first.
func ParseUSM(content []byte) (USMParams, error) {
	var p USMParams
	rest := content
	if len(rest) < 2 || rest[0] != 0x30 {
		return p, errBadUSM
	}
	rest, err := berContent(rest[1:])
	if err != nil {
		return p, err
	}
	if p.EngineID, rest, err = berOctetString(rest); err != nil {
		return p, err
	}
	if p.Boots, rest, err = berUint32(rest); err != nil {
		return p, err
	}
	if p.Time, rest, err = berUint32(rest); err != nil {
		return p, err
	}
	if p.UserName, rest, err = berString(rest); err != nil {
		return p, err
	}
	if p.AuthParams, rest, err = berOctetString(rest); err != nil {
		return p, err
	}
	if p.PrivParams, _, err = berOctetString(rest); err != nil {
		return p, err
	}
	return p, nil
}

// BuildV3 assembles a complete SNMPv3 message. flags select
// auth/priv/reportable. usm is marshalled as-is (AuthParams/PrivParams
// already sized). scopedContent is the full scopedPDU content (context
// engine ID/name + PDU TLV) — it is encrypted in place when privFlag.
// privEncrypt, when non-nil, encrypts the scopedPDU content and returns
// the OCTET STRING TLV to embed.
func BuildV3(h V3Header, usm USMParams, scoped []byte, privEncrypt func(plain []byte) ([]byte, error)) ([]byte, error) {
	var content []byte
	content = AppendInteger(content, Version3)

	// msgHeader
	var hdr []byte
	hdr = AppendInteger(hdr, h.MsgID)
	hdr = AppendInteger(hdr, h.MsgMaxSize)
	hdr = append(hdr, 0x04, 0x01, h.MsgFlags)
	hdr = AppendInteger(hdr, h.SecModel)
	content = AppendTLV(content, 0x30, hdr)

	// security parameters: USM (SEQUENCE) or TSM (empty per RFC 5591)
	if h.SecModel == SecurityModelTSM {
		content = append(content, 0x04, 0x00)
	} else {
		// USM security parameters (OCTET STRING wrapping a SEQUENCE)
		var usmBody []byte
		usmBody = AppendOctetString(usmBody, usm.EngineID)
		usmBody = AppendUint32(usmBody, usm.Boots)
		usmBody = AppendUint32(usmBody, usm.Time)
		usmBody = AppendOctetString(usmBody, []byte(usm.UserName))
		if h.MsgFlags&MsgFlagAuth != 0 {
			usmBody = AppendOctetString(usmBody, usm.AuthParams)
		} else {
			usmBody = append(usmBody, 0x04, 0x00)
		}
		if h.MsgFlags&MsgFlagPriv != 0 && h.MsgFlags&MsgFlagAuth != 0 {
			usmBody = AppendOctetString(usmBody, usm.PrivParams)
		} else {
			usmBody = append(usmBody, 0x04, 0x00)
		}
		content = AppendOctetString(content, AppendTLV(nil, 0x30, usmBody))
	}

	// scopedPDU: encrypt in place when requested. gosnmp (and RFC 3412
	// practice) encrypt the FULL scopedPDU TLV (SEQUENCE header included),
	// so wrap the content in its SEQUENCE TLV first, then hand the whole
	// TLV to the encryptor.
	if privEncrypt != nil {
		enc, err := privEncrypt(AppendTLV(nil, 0x30, scoped))
		if err != nil {
			return nil, err
		}
		content = append(content, enc...)
	} else {
		content = AppendTLV(content, 0x30, scoped)
	}

	var out []byte
	out = AppendTLV(out, 0x30, content)
	return out, nil
}

// BuildScoped builds scopedPDU content (context engine ID/name + raw PDU).
func BuildScoped(ctxEngineID, ctxName, pdu []byte) []byte {
	var sc []byte
	sc = AppendOctetString(sc, ctxEngineID)
	sc = AppendOctetString(sc, ctxName)
	sc = append(sc, pdu...)
	return sc
}

// --- priv crypto shared with the usm package --------------------------------

// EncryptAES encodes plaintext into an OCTET STRING TLV of AES-CFB
// ciphertext (RFC 3414 8.1.1 / RFC 3826): IV = boots | time | salt.
func EncryptAES(plain, key, boots, timeBytes, salt []byte) []byte {
	iv := make([]byte, 16)
	copy(iv[0:4], boots)
	copy(iv[4:8], timeBytes)
	copy(iv[8:16], salt)
	return cfbEncryptTLV(plain, key, iv)
}

// DecryptAES decodes AES-CFB ciphertext (content without the OCTET STRING
// TLV wrapper).
func DecryptAES(cipherText, key, boots, timeBytes, salt []byte) ([]byte, error) {
	iv := make([]byte, 16)
	copy(iv[0:4], boots)
	copy(iv[4:8], timeBytes)
	copy(iv[8:16], salt)
	return cfbDecrypt(cipherText, key, iv)
}

// EncryptDES encodes plaintext into an OCTET STRING TLV of DES-CBC
// ciphertext with zero padding (RFC 3414 8.1.1.1): IV = key[8:16] XOR salt.
func EncryptDES(plain, key, salt []byte) []byte {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		return nil
	}
	iv := make([]byte, 8)
	for i := 0; i < 8; i++ {
		iv[i] = key[8+i] ^ salt[i]
	}
	padded := padBlock(plain, des.BlockSize)
	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)
	var out []byte
	out = AppendOctetString(out, ct)
	return out
}

// DecryptDES decodes DES-CBC ciphertext content.
func DecryptDES(cipherText, key, salt []byte) ([]byte, error) {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	if len(cipherText)%des.BlockSize != 0 {
		return nil, errShortPriv
	}
	iv := make([]byte, 8)
	for i := 0; i < 8; i++ {
		iv[i] = key[8+i] ^ salt[i]
	}
	pt := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pt, cipherText)
	return pt, nil
}

func cfbEncryptTLV(plain, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	ct := make([]byte, len(plain))
	//lint:ignore SA1019 SNMPv3 privacy (RFC 3826 AES-CFB, RFC 3414 DES-CFB) mandates CFB mode on the wire; AEAD would break interop.
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ct, plain)
	var out []byte
	out = AppendOctetString(out, ct)
	return out
}

func cfbDecrypt(ct, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	//lint:ignore SA1019 SNMPv3 privacy (RFC 3826 AES-CFB, RFC 3414 DES-CFB) mandates CFB mode on the wire; AEAD would break interop.
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(pt, ct)
	return pt, nil
}

func padBlock(b []byte, block int) []byte {
	n := block - len(b)%block
	return append(b, make([]byte, n)...)
}

// --- small BER helpers local to v3 -------------------------------------------

func berSingleOctet(buf []byte) (byte, []byte, error) {
	if len(buf) < 2 || buf[0] != 0x04 {
		return 0, nil, errBadV3
	}
	if buf[1] != 0x01 {
		return 0, nil, errBadV3
	}
	if len(buf) < 3 {
		return 0, nil, errBadV3
	}
	return buf[2], buf[3:], nil
}

func berUint32(buf []byte) (uint32, []byte, error) {
	if len(buf) == 0 || buf[0] != 0x02 {
		return 0, nil, errBadV3
	}
	l, rest, err := berLen(buf[1:])
	if err != nil {
		return 0, nil, err
	}
	if l == 0 || l > 5 || len(rest) < l {
		return 0, nil, errBadV3
	}
	var v uint32
	for i := 0; i < l; i++ {
		v = v<<8 | uint32(rest[i])
	}
	return v, rest[l:], nil
}

func berString(buf []byte) (string, []byte, error) {
	b, rest, err := berOctetString(buf)
	if err != nil {
		return "", nil, err
	}
	return string(b), rest, nil
}
