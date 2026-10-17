// translate_helpers.go: byte-level PDU helpers, per-engine key caching and
// the shared inbound notification path used by both translators.
package usm

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/kattelma/snmp-proxy/internal/msg"
)

// --- per-engine key cache ---------------------------------------------------

// keyCache compiles the configured users against remote engine IDs on
// demand (keys are localized per engine). Used for validating inbound
// notifications, whose engine is the sending proxy's engine.
type keyCache struct {
	users    []Profile
	mu       sync.Mutex
	byEngine map[string]*Profiles // hex(engineID) -> compiled profiles
}

func newKeyCache(users []Profile) *keyCache {
	return &keyCache{users: users, byEngine: make(map[string]*Profiles)}
}

func (kc *keyCache) profilesFor(engineID []byte) (*Profiles, error) {
	key := fmt.Sprintf("%x", engineID)
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if p, ok := kc.byEngine[key]; ok {
		return p, nil
	}
	p, err := NewProfiles(kc.users, engineID)
	if err != nil {
		return nil, err
	}
	kc.byEngine[key] = p
	return p, nil
}

// --- per-engine replay cache (inbound notifications) ------------------------

// trapState is the highest accepted (boots, time) seen from one engine.
type trapState struct {
	boots uint32
	time  uint32
}

// replayCache enforces anti-replay for inbound notifications: per engine,
// (boots, time) must be monotonically non-decreasing. The first message
// from an engine is adopted as the floor.
type replayCache struct {
	mu    sync.Mutex
	byEng map[string]trapState
}

func newReplayCache() *replayCache {
	return &replayCache{byEng: make(map[string]trapState)}
}

func (rc *replayCache) accept(engineID []byte, boots, t uint32) error {
	key := fmt.Sprintf("%x", engineID)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	cur, ok := rc.byEng[key]
	switch {
	case !ok || boots > cur.boots:
		rc.byEng[key] = trapState{boots: boots, time: t}
		return nil
	case boots == cur.boots && t >= cur.time:
		rc.byEng[key] = trapState{boots: boots, time: t}
		return nil
	default:
		return ErrNotInTime
	}
}

// --- inbound notification path (shared) -------------------------------------

// receiveNotif authenticates and unwraps an inbound v3 trap/inform using
// per-engine keys (no discovery: notifications carry their own engine
// parameters) and enforces the per-engine replay cache. It returns the
// matched profile and the inner PDU TLV.
func (t *translatorBase) receiveNotif(packet []byte, m *msg.V3Message) (*compiled, []byte, error) {
	keys, err := t.keys.profilesFor(m.USM.EngineID)
	if err != nil {
		return nil, nil, err
	}
	c, ok := keys.Lookup(m.USM.UserName)
	if !ok {
		return nil, nil, ErrUnknownUser
	}
	wantAuth := m.Header.MsgFlags&msg.MsgFlagAuth != 0
	if wantAuth {
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
	if err := t.replay.accept(m.USM.EngineID, m.USM.Boots, m.USM.Time); err != nil {
		return nil, nil, err
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

// translatorBase carries the state shared by both translators: the user
// key cache, the notification replay cache, and the salt counter.
type translatorBase struct {
	keys    *keyCache
	replay  *replayCache
	salt    SaltCounter
}

// --- usmStats report helpers --------------------------------------------------

// usmStatsOIDFor maps a failure cause to its usmStats counter OID bytes
// (1.3.6.1.6.3.15.1.1.x.0).
func usmStatsOIDFor(cause error) []byte {
	var suffix uint64
	switch {
	case is(cause, ErrUnknownEngine):
		suffix = 4 // usmStatsUnknownEngineIDs
	case is(cause, ErrNotInTime):
		suffix = 2 // usmStatsNotInTimeWindows
	case is(cause, ErrUnknownUser):
		suffix = 3 // usmStatsUnknownUserNames
	case is(cause, ErrBadAuth):
		suffix = 5 // usmStatsWrongDigests
	case is(cause, ErrUnsupportedSec):
		suffix = 1 // usmStatsUnsupportedSecLevels
	default:
		suffix = 6 // usmStatsDecryptionErrors
	}
	// 1.3.6.1.6.3.15.1.1.suffix.0
	oid, err := msg.EncodeOID("1.3.6.1.6.3.15.1.1." + fmt.Sprint(suffix) + ".0")
	if err != nil {
		return []byte{0x2b, 6, 3, 15, 1, 1, byte(suffix), 0}
	}
	return oid
}

// is reports whether target is in err's chain (errors.Is without pulling
// the stdlib import into more files).
func is(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// reportVarbinds builds the varbind list content: one binding
// (counter-OID, INTEGER 0).
func reportVarbinds(oid []byte) []byte {
	var vb []byte
	vb = appendBinding(vb, oid, 0x02, []byte{0})
	return vb
}

func appendBinding(dst, oid []byte, valTag byte, val []byte) []byte {
	b := append(AppendTLVNil(0x06, oid), AppendTLVNil(valTag, val)...)
	return append(dst, AppendTLVNil(0x30, b)...)
}

// --- v3 scopedPDU / crypto plumbing ----------------------------------------

// scopedContent returns the scopedPDU SEQUENCE content when plaintext.
func scopedContent(scopedTLV []byte) ([]byte, error) {
	if len(scopedTLV) < 2 || scopedTLV[0] != 0x30 {
		return nil, ErrUnsupportedSec
	}
	// berContentOf expects the length-octet position: skip the tag.
	return berContentOf(scopedTLV[1:])
}

// scopedCiphertext returns the ciphertext content when the scopedPDU TLV
// is an OCTET STRING (encrypted).
func scopedCiphertext(scopedTLV []byte) ([]byte, error) {
	if len(scopedTLV) < 2 || scopedTLV[0] != 0x04 {
		return nil, ErrUnsupportedSec
	}
	// berContentOf expects the length-octet position: skip the tag.
	return berContentOf(scopedTLV[1:])
}

func decryptScoped(p PrivProtocol, key []byte, boots, etime uint32, privParams, ct []byte) ([]byte, error) {
	if len(privParams) < 8 {
		return nil, ErrUnsupportedSec
	}
	switch p {
	case PrivAES, PrivAES192, PrivAES256, PrivAES192C, PrivAES256C:
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:4], boots)
		binary.BigEndian.PutUint32(iv[4:8], etime)
		copy(iv[8:16], privParams[:8])
		return msg.DecryptAES(ct, key, iv[0:4], iv[4:8], iv[8:16])
	case PrivDES:
		return msg.DecryptDES(ct, key, privParams[:8])
	default:
		return nil, ErrUnsupportedSec
	}
}

func encryptScoped(p PrivProtocol, key []byte, boots, etime uint32, privParams, plain []byte) ([]byte, error) {
	if len(privParams) < 8 {
		return nil, ErrUnsupportedSec
	}
	switch p {
	case PrivAES, PrivAES192, PrivAES256, PrivAES192C, PrivAES256C:
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:4], boots)
		binary.BigEndian.PutUint32(iv[4:8], etime)
		copy(iv[8:16], privParams[:8])
		return msg.EncryptAES(plain, key, iv[0:4], iv[4:8], iv[8:16]), nil
	case PrivDES:
		return msg.EncryptDES(plain, key, privParams), nil
	default:
		return nil, ErrUnsupportedSec
	}
}

// --- PDU byte-level helpers (shared by both translators) --------------

// pduCommon extracts the common fields of a raw PDU TLV (tag octet +
// length + body of reqID, errStatus, errIndex, varbinds) via the shared
// msg.ParsePDU parser.
func pduCommon(pdu []byte) (msg.PDUFields, bool) {
	_, f, err := msg.ParsePDU(pdu)
	if err != nil {
		return msg.PDUFields{}, false
	}
	return f, true
}

// varbindsOf returns the varbind list content from a raw PDU TLV.
func varbindsOf(pdu []byte) []byte {
	if f, ok := pduCommon(pdu); ok {
		return f.Varbinds
	}
	return []byte{0}
}

func varbindContent(pdu []byte) ([]byte, error) {
	f, ok := pduCommon(pdu)
	if !ok {
		return nil, ErrNoPending
	}
	return f.Varbinds, nil
}

// locateAuthParams finds the byte offset of the authParams OCTET STRING
// content within a marshalled v3 message (for zeroing during verification
// and for splicing the digest after signing).
func locateAuthParams(packet []byte, m *msg.V3Message) (int, bool) {
	return findAuthParamsOffset(packet)
}

// findAuthParamsOffset re-parses the wire bytes with byte-exact positions:
// outer SEQUENCE | ver | header | secParams OCTET STRING (engineID, boots,
// time, userName, authParams...).
func findAuthParamsOffset(packet []byte) (int, bool) {
	rest := packet
	// outer SEQUENCE tag+len
	if len(rest) < 2 || rest[0] != 0x30 {
		return 0, false
	}
	l, rest, err := berLenAt(rest[1:])
	if err != nil {
		return 0, false
	}
	_ = l
	// version INTEGER
	if _, rest, err = readInt32(rest); err != nil {
		return 0, false
	}
	// header SEQUENCE
	if len(rest) < 2 || rest[0] != 0x30 {
		return 0, false
	}
	hdrLen, rest, err := berLenAt(rest[1:])
	if err != nil {
		return 0, false
	}
	_ = hdrLen
	// skip msgID, msgMaxSize
	if _, rest, err = readInt32(rest); err != nil {
		return 0, false
	}
	if _, rest, err = readInt32(rest); err != nil {
		return 0, false
	}
	// msgFlags OCTET STRING
	if len(rest) < 2 || rest[0] != 0x04 {
		return 0, false
	}
	fl, rest, err := berLenAt(rest[1:])
	if err != nil {
		return 0, false
	}
	if len(rest) < fl {
		return 0, false
	}
	rest = rest[fl:]
	// secModel INTEGER
	if _, rest, err = readInt32(rest); err != nil {
		return 0, false
	}
	// secParams OCTET STRING
	if len(rest) < 2 || rest[0] != 0x04 {
		return 0, false
	}
	spLen, rest, err := berLenAt(rest[1:])
	if err != nil {
		return 0, false
	}
	if len(rest) < spLen {
		return 0, false
	}
	spStart := len(packet) - len(rest) // global offset of secParams content
	sp := rest[:spLen]
	// inside secParams: SEQUENCE (engineID, boots, time, userName, authParams)
	if len(sp) < 2 || sp[0] != 0x30 {
		return 0, false
	}
	spOff := spStart + 2 // SEQUENCE tag + length octet
	sp, err = berContentOf(sp[1:])
	if err != nil {
		return 0, false
	}
	// engineID
	if len(sp) < 2 || sp[0] != 0x04 {
		return 0, false
	}
	idLen, sp2, err := berLenAt(sp[1:])
	if err != nil || len(sp2) < idLen {
		return 0, false
	}
	sp2 = sp2[idLen:]
	// boots
	if _, sp2, err = readUint32(sp2); err != nil {
		return 0, false
	}
	// time
	if _, sp2, err = readUint32(sp2); err != nil {
		return 0, false
	}
	// userName
	if len(sp2) < 2 || sp2[0] != 0x04 {
		return 0, false
	}
	unLen, sp2, err := berLenAt(sp2[1:])
	if err != nil || len(sp2) < unLen {
		return 0, false
	}
	sp2 = sp2[unLen:]
	// authParams OCTET STRING: offset of its CONTENT within the packet.
	// sp is a sub-slice of packet: offsets inside sp must be translated.
	if len(sp2) < 2 || sp2[0] != 0x04 {
		return 0, false
	}
	apLen, sp3, err := berLenAt(sp2[1:])
	if err != nil || len(sp3) < apLen {
		return 0, false
	}
	// authParams content = spOff + offset of the TLV within sp + 2 header bytes
	contentOff := spOff + (len(sp) - len(sp2)) + 2
	if contentOff < 0 || contentOff+apLen > len(packet) {
		return 0, false
	}
	return contentOff, true
}
