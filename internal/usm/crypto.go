// Package usm implements the User-based Security Model (RFC 3414) pieces
// needed by the translate mode: password-to-key derivation, message
// authentication (MD5/SHA1 per RFC 3414, SHA-2 per RFC 7860), privacy
// (AES-CFB, DES-CBC), and the v1/v2c <-> v3 translation forwarders.
package usm

import (
	"crypto"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"
	_ "crypto/sha256" // register SHA224/SHA256
	_ "crypto/sha512" // register SHA384/SHA512
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// AuthProtocol enumerates the supported authentication protocols.
type AuthProtocol int

const (
	AuthNone   AuthProtocol = 1
	AuthMD5    AuthProtocol = 2
	AuthSHA    AuthProtocol = 3
	AuthSHA224 AuthProtocol = 4
	AuthSHA256 AuthProtocol = 5
	AuthSHA384 AuthProtocol = 6
	AuthSHA512 AuthProtocol = 7
)

// PrivProtocol enumerates the supported privacy protocols.
type PrivProtocol int

const (
	PrivNone    PrivProtocol = 1
	PrivDES     PrivProtocol = 2
	PrivAES     PrivProtocol = 3  // AES-128 (CFB)
	PrivAES192  PrivProtocol = 4  // Blumenthal extension
	PrivAES256  PrivProtocol = 5  // Blumenthal extension
	PrivAES192C PrivProtocol = 6  // Reeder extension
	PrivAES256C PrivProtocol = 7  // Reeder extension
)

// ErrAuth is returned when authentication fails verification.
var ErrAuth = errors.New("usm: authentication failed")

// hashFunc maps the protocol to its crypto.Hash (MD5/SHA1/SHA-2 family).
func (a AuthProtocol) hashFunc() (crypto.Hash, error) {
	switch a {
	case AuthMD5:
		return crypto.MD5, nil
	case AuthSHA:
		return crypto.SHA1, nil
	case AuthSHA224:
		return crypto.SHA224, nil
	case AuthSHA256:
		return crypto.SHA256, nil
	case AuthSHA384:
		return crypto.SHA384, nil
	case AuthSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("usm: no hash for auth protocol %d", int(a))
	}
}

// MacLength returns the authentication digest length on the wire.
func (a AuthProtocol) MacLength() int {
	switch a {
	case AuthMD5, AuthSHA:
		return 12
	case AuthSHA224:
		return 16
	case AuthSHA256:
		return 24
	case AuthSHA384:
		return 32
	case AuthSHA512:
		return 48
	default:
		return 0
	}
}

// KeyLength returns the localized auth key length.
func (a AuthProtocol) KeyLength() int {
	switch a {
	case AuthMD5:
		return 16
	case AuthSHA:
		return 20
	case AuthSHA224:
		return 28
	case AuthSHA256:
		return 32
	case AuthSHA384:
		return 48
	case AuthSHA512:
		return 64
	default:
		return 0
	}
}

// PrivKeyLength returns the privacy key length.
func (p PrivProtocol) PrivKeyLength() int {
	switch p {
	case PrivDES, PrivAES:
		return 16
	case PrivAES192, PrivAES192C:
		return 24
	case PrivAES256, PrivAES256C:
		return 32
	default:
		return 0
	}
}

// ParseAuthProtocol maps config strings to AuthProtocol.
func ParseAuthProtocol(s string) (AuthProtocol, error) {
	switch s {
	case "", "none":
		return AuthNone, nil
	case "md5":
		return AuthMD5, nil
	case "sha", "sha1":
		return AuthSHA, nil
	case "sha224":
		return AuthSHA224, nil
	case "sha256":
		return AuthSHA256, nil
	case "sha384":
		return AuthSHA384, nil
	case "sha512":
		return AuthSHA512, nil
	default:
		return 0, fmt.Errorf("usm: unknown auth protocol %q", s)
	}
}

// ParsePrivProtocol maps config strings to PrivProtocol.
func ParsePrivProtocol(s string) (PrivProtocol, error) {
	switch s {
	case "", "none":
		return PrivNone, nil
	case "des":
		return PrivDES, nil
	case "aes", "aes128":
		return PrivAES, nil
	case "aes192":
		return PrivAES192, nil
	case "aes256":
		return PrivAES256, nil
	case "aes192c":
		return PrivAES192C, nil
	case "aes256c":
		return PrivAES256C, nil
	default:
		return 0, fmt.Errorf("usm: unknown privacy protocol %q", s)
	}
}

// PasswordToKey derives the localized authentication key (RFC 3414 2.6
// with RFC 7860 hash extension): hash the password (1MiB cycling), then
// localize with the engine ID: local = H(H | engineID | H).
func PasswordToKey(a AuthProtocol, password, engineID string) ([]byte, error) {
	hf, err := a.hashFunc()
	if err != nil {
		return nil, err
	}
	hashed, err := hashPassword(hf.New, password)
	if err != nil {
		return nil, err
	}
	return localize(hf.New, hashed, engineID), nil
}

// hashPassword runs the RFC 3414 2.6 password-to-key loop: 1048576 bytes
// of the password cycled in 64-byte chunks through the hash.
func hashPassword(hfNew func() hash.Hash, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("usm: empty password")
	}
	h := hfNew()
	var pi int
	buf := make([]byte, 64)
	for i := 0; i < 1048576; i += 64 {
		for j := 0; j < 64; j++ {
			buf[j] = password[pi%len(password)]
			pi++
		}
		h.Write(buf)
	}
	return h.Sum(nil), nil
}

// localize = H(hashed | engineID | hashed).
func localize(hfNew func() hash.Hash, hashed []byte, engineID string) []byte {
	h := hfNew()
	h.Write(hashed)
	h.Write([]byte(engineID))
	h.Write(hashed)
	return h.Sum(nil)
}

// LocalizedKey returns the full localized privacy key for a user,
// applying Blumenthal or Reeder extension for the AES-192/256 variants
// (matching gosnmp/net-snmp behavior).
func LocalizedPrivKey(a AuthProtocol, p PrivProtocol, password, engineID string) ([]byte, error) {
	hf, err := a.hashFunc()
	if err != nil {
		return nil, err
	}
	hashed, err := hashPassword(hf.New, password)
	if err != nil {
		return nil, err
	}
	local := localize(hf.New, hashed, engineID)

	want := p.PrivKeyLength()
	if want == 0 {
		return nil, fmt.Errorf("usm: no key for priv protocol %d", int(p))
	}
	switch p {
	case PrivAES, PrivDES:
		// key[:16] of the localized auth key (RFC 3414 8.x uses the
		// localized auth key as the priv key for DES/AES-128).
		if len(local) < want {
			return nil, errors.New("usm: localized key too short")
		}
		return local[:want], nil
	case PrivAES192, PrivAES256:
		// Blumenthal: local || H(local)
		ext := hashData(hf.New, local)
		key := append(append([]byte{}, local...), ext...)
		return key[:want], nil
	case PrivAES192C, PrivAES256C:
		// Reeder: local || H(local | engineID | local) (re-localize).
		ext := localize(hf.New, local, engineID)
		key := append(append([]byte{}, local...), ext...)
		return key[:want], nil
	default:
		return nil, fmt.Errorf("usm: unsupported priv protocol %d", int(p))
	}
}

func hashData(hfNew func() hash.Hash, data []byte) []byte {
	h := hfNew()
	h.Write(data)
	return h.Sum(nil)
}

// Digest computes the message authentication digest over the packet bytes
// (auth params zeroed) with the localized auth key.
func Digest(a AuthProtocol, packet, authKey []byte) ([]byte, error) {
	switch a {
	case AuthMD5, AuthSHA:
		return digestRFC3414(a, packet, authKey)
	case AuthSHA224, AuthSHA256, AuthSHA384, AuthSHA512:
		hf, err := a.hashFunc()
		if err != nil {
			return nil, err
		}
		mac := hmac.New(hf.New, authKey)
		mac.Write(packet)
		return mac.Sum(nil)[:a.MacLength()], nil
	default:
		return nil, fmt.Errorf("usm: cannot digest with protocol %d", int(a))
	}
}

// digestRFC3414 computes the MD5/SHA1 HMAC-style digest (RFC 3414 6.3.2 /
// 7.3.2): H(k2 | H(k1 | packet)) truncated to 12 bytes, with the 64-byte
// XOR-padded key extensions.
func digestRFC3414(a AuthProtocol, packet, authKey []byte) ([]byte, error) {
	var h1, h2 interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
	switch a {
	case AuthMD5:
		h1, h2 = md5.New(), md5.New()
	case AuthSHA:
		h1, h2 = sha1.New(), sha1.New()
	default:
		return nil, fmt.Errorf("usm: digestRFC3414 on protocol %d", int(a))
	}
	var extkey [64]byte
	copy(extkey[:], authKey)
	k1 := make([]byte, 64)
	k2 := make([]byte, 64)
	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}
	h1.Write(k1)
	h1.Write(packet)
	d1 := h1.Sum(nil)
	h2.Write(k2)
	h2.Write(d1)
	return h2.Sum(nil)[:12], nil
}

// Sign marks a packet authenticated: it computes the digest over packet
// (auth params must already be zeroed in packet) and returns it for the
// caller to splice into the wire bytes.
func Sign(a AuthProtocol, packet, authKey []byte) ([]byte, error) {
	return Digest(a, packet, authKey)
}

// Verify checks a packet's auth digest. authParamsOff points at the
// authParams OCTET STRING TLV inside packet; it is zeroed in place during
// the check and restored afterwards.
func Verify(a AuthProtocol, packet, authKey, authParams []byte, authParamsOff int) error {
	want := a.MacLength()
	if len(authParams) != want {
		return fmt.Errorf("usm: auth params len %d, want %d", len(authParams), want)
	}
	// copy first: authParams may alias packet (zeroing packet would
	// otherwise zero the expected digest too)
	wantDigest := append([]byte{}, packet[authParamsOff:authParamsOff+len(authParams)]...)
	for i := 0; i < len(wantDigest); i++ {
		packet[authParamsOff+i] = 0
	}
	defer copy(packet[authParamsOff:authParamsOff+len(authParams)], wantDigest)
	digest, err := Digest(a, packet, authKey)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, wantDigest) != 1 {
		return ErrAuth
	}
	return nil
}

// SaltCounter is the per-engine privacy salt source (RFC 3414 8.1.1.1:
// incremented on every encrypted packet).
type SaltCounter struct {
	v uint64
}

// Next returns the next AES salt (8 bytes BE).
func (s *SaltCounter) NextAES() []byte {
	s.v++
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, s.v)
	return b
}

// NextDES returns the next DES salt: boots(4) | counter(4).
func (s *SaltCounter) NextDES(boots uint32) []byte {
	s.v++
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], boots)
	binary.BigEndian.PutUint32(b[4:], uint32(s.v))
	return b
}

// DesBlockSize is re-exported for callers building DES packets.
const DesBlockSize = des.BlockSize
