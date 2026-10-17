// Unit tests for the USM crypto primitives (crypto.go): protocol parsing,
// key lengths, RFC 3414 A.3 password-to-key vectors, localized priv keys
// (Blumenthal/Reeder extensions), digest/sign/verify and the salt counter.
package usm

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseAuthProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want AuthProtocol
		ok   bool
	}{
		{"", AuthNone, true},
		{"none", AuthNone, true},
		{"md5", AuthMD5, true},
		{"sha", AuthSHA, true},
		{"sha1", AuthSHA, true},
		{"sha224", AuthSHA224, true},
		{"sha256", AuthSHA256, true},
		{"sha384", AuthSHA384, true},
		{"sha512", AuthSHA512, true},
		{"SHA", 0, false},
		{"bogus", 0, false},
	}
	for _, c := range cases {
		got, err := ParseAuthProtocol(c.in)
		if c.ok {
			if err != nil {
				t.Fatalf("ParseAuthProtocol(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("ParseAuthProtocol(%q) = %d, want %d", c.in, got, c.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("ParseAuthProtocol(%q): expected error", c.in)
		}
	}
}

func TestParsePrivProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want PrivProtocol
		ok   bool
	}{
		{"", PrivNone, true},
		{"none", PrivNone, true},
		{"des", PrivDES, true},
		{"aes", PrivAES, true},
		{"aes128", PrivAES, true},
		{"aes192", PrivAES192, true},
		{"aes256", PrivAES256, true},
		{"aes192c", PrivAES192C, true},
		{"aes256c", PrivAES256C, true},
		{"AES", 0, false},
		{"bogus", 0, false},
	}
	for _, c := range cases {
		got, err := ParsePrivProtocol(c.in)
		if c.ok {
			if err != nil {
				t.Fatalf("ParsePrivProtocol(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("ParsePrivProtocol(%q) = %d, want %d", c.in, got, c.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("ParsePrivProtocol(%q): expected error", c.in)
		}
	}
}

func TestKeyLengths(t *testing.T) {
	// MacLength: digest length on the wire.
	mac := map[AuthProtocol]int{
		AuthMD5: 12, AuthSHA: 12, AuthSHA224: 16, AuthSHA256: 24,
		AuthSHA384: 32, AuthSHA512: 48, AuthNone: 0,
	}
	for a, want := range mac {
		if got := a.MacLength(); got != want {
			t.Fatalf("MacLength(%d) = %d, want %d", a, got, want)
		}
	}
	// KeyLength: localized auth key length.
	key := map[AuthProtocol]int{
		AuthMD5: 16, AuthSHA: 20, AuthSHA224: 28, AuthSHA256: 32,
		AuthSHA384: 48, AuthSHA512: 64, AuthNone: 0,
	}
	for a, want := range key {
		if got := a.KeyLength(); got != want {
			t.Fatalf("KeyLength(%d) = %d, want %d", a, got, want)
		}
	}
	// PrivKeyLength: privacy key length.
	priv := map[PrivProtocol]int{
		PrivDES: 16, PrivAES: 16, PrivAES192: 24, PrivAES256: 32,
		PrivAES192C: 24, PrivAES256C: 32, PrivNone: 0,
	}
	for p, want := range priv {
		if got := p.PrivKeyLength(); got != want {
			t.Fatalf("PrivKeyLength(%d) = %d, want %d", p, got, want)
		}
	}
}

// RFC 3414 A.3 reference vectors (password "maplesyrup", engine ID
// 00 00 00 00 00 00 00 00 00 00 00 02).
func TestPasswordToKeyRFC3414(t *testing.T) {
	eid := string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	md5Key, err := PasswordToKey(AuthMD5, "maplesyrup", eid)
	if err != nil {
		t.Fatalf("PasswordToKey MD5: %v", err)
	}
	wantMD5, _ := hexDecode("526f5eed9fcce26f8964c2930787d82b")
	if !bytes.Equal(md5Key, wantMD5) {
		t.Fatalf("MD5 key = %x, want %x", md5Key, wantMD5)
	}
	shaKey, err := PasswordToKey(AuthSHA, "maplesyrup", eid)
	if err != nil {
		t.Fatalf("PasswordToKey SHA: %v", err)
	}
	wantSHA, _ := hexDecode("6695febc9288e36282235fc7151f128497b38f3f")
	if !bytes.Equal(shaKey, wantSHA) {
		t.Fatalf("SHA key = %x, want %x", shaKey, wantSHA)
	}
}

func TestPasswordToKeyErrors(t *testing.T) {
	if _, err := PasswordToKey(AuthNone, "pw", "eid"); err == nil {
		t.Fatal("AuthNone: expected error (no hash)")
	}
	if _, err := PasswordToKey(AuthSHA, "", "eid"); err == nil {
		t.Fatal("empty password: expected error")
	}
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok := hexNibble(s[2*i])
		lo, ok2 := hexNibble(s[2*i+1])
		if !ok || !ok2 {
			return nil, errors.New("bad hex")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func TestLocalizedPrivKey(t *testing.T) {
	const (
		password = "maplesyrup"
		eid      = "\x80\x00\x1d\x04test"
	)
	shaKey, err := PasswordToKey(AuthSHA, password, eid)
	if err != nil {
		t.Fatalf("PasswordToKey: %v", err)
	}

	// AES-128 / DES: first 16 bytes of the localized auth key.
	for _, p := range []PrivProtocol{PrivAES, PrivDES} {
		k, err := LocalizedPrivKey(AuthSHA, p, password, eid)
		if err != nil {
			t.Fatalf("LocalizedPrivKey(%d): %v", p, err)
		}
		if len(k) != 16 || !bytes.Equal(k, shaKey[:16]) {
			t.Fatalf("LocalizedPrivKey(%d) = %x, want local[:16] %x", p, k, shaKey[:16])
		}
	}

	// Blumenthal extensions (AES-192/256): local || H_auth(local) — the
	// extension hash uses the AUTH protocol's hash (SHA-1 for AuthSHA),
	// matching gosnmp extendKeyBlumenthal.
	for _, tc := range []struct {
		p    PrivProtocol
		want int
	}{
		{PrivAES192, 24}, {PrivAES256, 32},
	} {
		k, err := LocalizedPrivKey(AuthSHA, tc.p, password, eid)
		if err != nil {
			t.Fatalf("LocalizedPrivKey(%d): %v", tc.p, err)
		}
		if len(k) != tc.want {
			t.Fatalf("LocalizedPrivKey(%d) len = %d, want %d", tc.p, len(k), tc.want)
		}
		if !bytes.Equal(k[:20], shaKey) {
			t.Fatalf("LocalizedPrivKey(%d) prefix != local", tc.p)
		}
		h := sha1.Sum(shaKey)
		if !bytes.Equal(k[20:], h[:tc.want-20]) {
			t.Fatalf("LocalizedPrivKey(%d) extension mismatch (Blumenthal)", tc.p)
		}
	}

	// Reeder extensions (AES-192C/256C): local || H_auth(local | engineID |
	// local) (re-localize with the auth hash), matching gosnmp
	// extendKeyReeder.
	for _, tc := range []struct {
		p    PrivProtocol
		want int
	}{
		{PrivAES192C, 24}, {PrivAES256C, 32},
	} {
		k, err := LocalizedPrivKey(AuthSHA, tc.p, password, eid)
		if err != nil {
			t.Fatalf("LocalizedPrivKey(%d): %v", tc.p, err)
		}
		if len(k) != tc.want {
			t.Fatalf("LocalizedPrivKey(%d) len = %d, want %d", tc.p, len(k), tc.want)
		}
		h := sha1.New()
		h.Write(shaKey)
		h.Write([]byte(eid))
		h.Write(shaKey)
		ext := h.Sum(nil)
		if !bytes.Equal(k[20:], ext[:tc.want-20]) {
			t.Fatalf("LocalizedPrivKey(%d) extension mismatch (Reeder)", tc.p)
		}
	}

	// Errors: unsupported priv protocol, empty password.
	if _, err := LocalizedPrivKey(AuthSHA, PrivNone, password, eid); err == nil {
		t.Fatal("PrivNone: expected error")
	}
	if _, err := LocalizedPrivKey(AuthSHA, PrivAES, "", eid); err == nil {
		t.Fatal("empty password: expected error")
	}
}

// buildAuthPacket returns a packet with an authParams area embedded at
// offset off, plus the params slice (aliasing the packet).
func buildAuthPacket(paramLen, off int) (packet, params []byte) {
	packet = make([]byte, off+paramLen+16)
	for i := range packet {
		packet[i] = byte(i * 7)
	}
	params = packet[off : off+paramLen]
	return packet, params
}

func TestDigestSignVerifyRFC3414(t *testing.T) {
	key, err := PasswordToKey(AuthSHA, "authpass", "eid")
	if err != nil {
		t.Fatalf("PasswordToKey: %v", err)
	}
	for _, a := range []AuthProtocol{AuthMD5, AuthSHA} {
		packet, params := buildAuthPacket(a.MacLength(), 8)
		for i := range params {
			params[i] = 0 // Sign/Verify operate on zeroed auth params
		}
		digest, err := Sign(a, packet, key)
		if err != nil {
			t.Fatalf("Sign(%d): %v", a, err)
		}
		if len(digest) != a.MacLength() {
			t.Fatalf("Sign(%d) len = %d, want %d", a, len(digest), a.MacLength())
		}
		copy(params, digest)
		if err := Verify(a, packet, key, params, 8); err != nil {
			t.Fatalf("Verify(%d): %v", a, err)
		}
		// tampered digest must fail
		packet2, params2 := buildAuthPacket(a.MacLength(), 8)
		for i := range params2 {
			params2[i] = 0
		}
		copy(params2, digest)
		params2[0] ^= 0xff
		if err := Verify(a, packet2, key, params2, 8); !errors.Is(err, ErrAuth) {
			t.Fatalf("Verify(%d) tampered: %v, want ErrAuth", a, err)
		}
	}
}

func TestDigestSignVerifySHA2(t *testing.T) {
	key, err := PasswordToKey(AuthSHA256, "authpass", "eid")
	if err != nil {
		t.Fatalf("PasswordToKey: %v", err)
	}
	for _, a := range []AuthProtocol{AuthSHA224, AuthSHA256, AuthSHA384, AuthSHA512} {
		// sign-then-verify round trip on zeroed params
		packet, params := buildAuthPacket(a.MacLength(), 8)
		for i := range params {
			params[i] = 0
		}
		digest, err := Digest(a, packet, key)
		if err != nil {
			t.Fatalf("Digest(%d): %v", a, err)
		}
		if len(digest) != a.MacLength() {
			t.Fatalf("Digest(%d) len = %d, want %d", a, len(digest), a.MacLength())
		}
		copy(params, digest)
		if err := Verify(a, packet, key, params, 8); err != nil {
			t.Fatalf("Verify(%d): %v", a, err)
		}
		// wrong key must fail
		other, _ := PasswordToKey(AuthSHA256, "otherpass", "eid")
		if err := Verify(a, packet, other, params, 8); !errors.Is(err, ErrAuth) {
			t.Fatalf("Verify(%d) wrong key: %v, want ErrAuth", a, err)
		}
	}
	// SHA-2 digest is an HMAC (RFC 7860): cross-check one value.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("payload"))
	want := mac.Sum(nil)[:AuthSHA256.MacLength()]
	got, err := Digest(AuthSHA256, []byte("payload"), key)
	if err != nil {
		t.Fatalf("Digest SHA256: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA256 digest = %x, want hmac %x", got, want)
	}
}

func TestVerifyParamsErrors(t *testing.T) {
	key, _ := PasswordToKey(AuthSHA, "pw", "eid")
	packet, params := buildAuthPacket(AuthSHA.MacLength(), 4)
	if err := Verify(AuthSHA, packet, key, params[:5], 4); err == nil {
		t.Fatal("wrong-length params: expected error")
	}
	if _, err := Digest(AuthNone, packet, key); err == nil {
		t.Fatal("Digest(AuthNone): expected error")
	}
}

// Verify must restore the authParams bytes it zeroed inside the packet.
func TestVerifyRestoresPacket(t *testing.T) {
	key, _ := PasswordToKey(AuthSHA, "pw", "eid")
	packet, params := buildAuthPacket(AuthSHA.MacLength(), 8)
	for i := range params {
		params[i] = 0
	}
	digest, err := Digest(AuthSHA, packet, key)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	copy(params, digest)
	orig := append([]byte{}, packet...)
	if err := Verify(AuthSHA, packet, key, params, 8); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Verify restores the params area to its pre-call contents (digest).
	if !bytes.Equal(packet, orig) {
		t.Fatal("Verify did not restore packet bytes")
	}
}

func TestSaltCounterDES(t *testing.T) {
	var s SaltCounter
	const boots = uint32(7)
	b1 := s.NextDES(boots)
	b2 := s.NextDES(boots)
	if len(b1) != 8 || len(b2) != 8 {
		t.Fatalf("NextDES len = %d/%d, want 8", len(b1), len(b2))
	}
	if got := binary.BigEndian.Uint32(b1[:4]); got != boots {
		t.Fatalf("NextDES boots = %d, want %d", got, boots)
	}
	if got := binary.BigEndian.Uint32(b1[4:]); got != 1 {
		t.Fatalf("NextDES counter1 = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(b2[4:]); got != 2 {
		t.Fatalf("NextDES counter2 = %d, want 2", got)
	}
	// AES salt shares the same counter.
	b3 := s.NextAES()
	if got := binary.BigEndian.Uint64(b3); got != 3 {
		t.Fatalf("NextAES counter = %d, want 3", got)
	}
}
