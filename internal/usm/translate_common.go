// translate_common.go: helpers shared by the manager-side and agent-side
// USM translators: v3 verification/unwrapping of inbound messages and
// signing of outbound messages.
package usm

import (
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// SignV3 is the exported form of signV3: it computes the auth digest
// over a marshalled v3 message (whose authParams must already be
// zero-filled) and splices it into the authParams TLV position. Exported
// for the CLI selftest probes (cmd cannot reach unexported helpers).
func SignV3(out []byte, auth AuthProtocol, authKey []byte) error {
	return signV3(out, auth, authKey)
}

// unwrapV3 authenticates (when flagged) and decrypts (when flagged) an
// inbound v3 message against the compiled profile named in the message,
// then unwraps the scopedPDU in place. It returns the matched profile and
// the inner PDU TLV.
func unwrapV3(keys *Profiles, m *msg.V3Message, packet []byte) (*compiled, []byte, error) {
	if keys == nil {
		return nil, nil, ErrUnknownEngine
	}
	c, ok := keys.Lookup(m.USM.UserName)
	if !ok {
		return nil, nil, ErrUnknownUser
	}
	if m.Header.MsgFlags&msg.MsgFlagAuth != 0 {
		if c.authKey == nil {
			return nil, nil, ErrUnsupportedSec
		}
		off, ok2 := locateAuthParams(packet, m)
		if !ok2 {
			return nil, nil, ErrBadAuth
		}
		if err := Verify(c.p.AuthProtocol, packet, c.authKey, m.USM.AuthParams, off); err != nil {
			return nil, nil, err
		}
	}
	if m.Header.MsgFlags&msg.MsgFlagPriv != 0 {
		if c.privKey == nil {
			return nil, nil, ErrUnsupportedSec
		}
		ct, err := scopedCiphertext(m.PDU)
		if err != nil {
			return nil, nil, err
		}
		plain, err := decryptScoped(c.p.PrivProtocol, c.privKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, ct)
		if err != nil {
			return nil, nil, err
		}
		if err := m.UnwrapScopedPDU(plain); err != nil {
			return nil, nil, err
		}
	} else {
		content, err := scopedContent(m.PDU)
		if err != nil {
			return nil, nil, err
		}
		if err := m.UnwrapScopedPDU(content); err != nil {
			return nil, nil, err
		}
	}
	return c, m.PDU, nil
}

// UnwrapV3 is the exported form of unwrapV3: it authenticates (when
// flagged) and decrypts (when flagged) an inbound v3 message against the
// compiled profile named in the message, then unwraps the scopedPDU in
// place. Returns the matched profile and the inner PDU TLV. Exported for
// the CLI selftest probes (cmd cannot reach unexported helpers).
func UnwrapV3(keys *Profiles, m *msg.V3Message, packet []byte) (profile *compiled, pdu []byte, err error) {
	return unwrapV3(keys, m, packet)
}

// signV3 computes the auth digest over a marshalled v3 message (whose
// authParams must already be zero-filled) and splices it into the
// authParams TLV position.
func signV3(out []byte, auth AuthProtocol, authKey []byte) error {
	off, ok := locateAuthParams(out, nil)
	if !ok {
		return ErrBadAuth
	}
	digest, err := Sign(auth, out, authKey)
	if err != nil {
		return err
	}
	copy(out[off:off+len(digest)], digest)
	return nil
}
