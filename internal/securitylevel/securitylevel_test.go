// Direct tests for the leaf protocol vocabulary: the config parsers, the
// crypto.Hash mapping and the RFC-defined key/digest lengths.
//
// internal/usm exercises these indirectly, but a leaf package with no test
// binary is invisible to coverage and, more importantly, a wrong length here
// is a wire-compatibility bug that only shows up against a third-party peer.
// These tables pin the numbers to the RFCs (3414, 3826, 7860, and the
// Blumenthal/Reeder AES extensions) and the enum values to the on-wire and
// on-disk representation.
package securitylevel

import (
	"crypto"
	"strings"
	"testing"
)

func TestAuthProtocolValuesAreStable(t *testing.T) {
	// The numeric values are part of the persisted config/engine-store
	// vocabulary. Renumbering them silently invalidates existing state, so
	// pin them explicitly.
	want := map[AuthProtocol]int{
		AuthNone: 1, AuthMD5: 2, AuthSHA: 3, AuthSHA224: 4,
		AuthSHA256: 5, AuthSHA384: 6, AuthSHA512: 7,
	}
	for p, n := range want {
		if int(p) != n {
			t.Fatalf("AuthProtocol %d has value %d, want %d", n, int(p), n)
		}
	}
}

func TestPrivProtocolValuesAreStable(t *testing.T) {
	want := map[PrivProtocol]int{
		PrivNone: 1, PrivDES: 2, PrivAES: 3, PrivAES192: 4,
		PrivAES256: 5, PrivAES192C: 6, PrivAES256C: 7,
	}
	for p, n := range want {
		if int(p) != n {
			t.Fatalf("PrivProtocol %d has value %d, want %d", n, int(p), n)
		}
	}
}

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
		// Parsing is deliberately case-sensitive: a config typo must fail
		// validation rather than silently select a protocol.
		{"SHA", 0, false},
		{"Md5", 0, false},
		{"sha-256", 0, false},
		{"sha512 ", 0, false},
		{"bogus", 0, false},
	}
	for _, c := range cases {
		got, err := ParseAuthProtocol(c.in)
		if !c.ok {
			if err == nil {
				t.Fatalf("ParseAuthProtocol(%q) = %d, want error", c.in, got)
			}
			if !strings.Contains(err.Error(), "unknown auth protocol") {
				t.Fatalf("ParseAuthProtocol(%q) error %q does not name the problem", c.in, err)
			}
			if got != 0 {
				t.Fatalf("ParseAuthProtocol(%q) returned %d with an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseAuthProtocol(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseAuthProtocol(%q) = %d, want %d", c.in, got, c.want)
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
		{"Aes128", 0, false},
		{"aes-128", 0, false},
		{"bogus", 0, false},
	}
	for _, c := range cases {
		got, err := ParsePrivProtocol(c.in)
		if !c.ok {
			if err == nil {
				t.Fatalf("ParsePrivProtocol(%q) = %d, want error", c.in, got)
			}
			if !strings.Contains(err.Error(), "unknown privacy protocol") {
				t.Fatalf("ParsePrivProtocol(%q) error %q does not name the problem", c.in, err)
			}
			if got != 0 {
				t.Fatalf("ParsePrivProtocol(%q) returned %d with an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParsePrivProtocol(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParsePrivProtocol(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestHashFunc(t *testing.T) {
	want := map[AuthProtocol]crypto.Hash{
		AuthMD5:    crypto.MD5,
		AuthSHA:    crypto.SHA1,
		AuthSHA224: crypto.SHA224,
		AuthSHA256: crypto.SHA256,
		AuthSHA384: crypto.SHA384,
		AuthSHA512: crypto.SHA512,
	}
	for p, h := range want {
		got, err := HashFunc(p)
		if err != nil {
			t.Fatalf("HashFunc(%d): %v", p, err)
		}
		if got != h {
			t.Fatalf("HashFunc(%d) = %v, want %v", p, got, h)
		}
	}

	// AuthNone is not a hash protocol; every unassigned value must error
	// rather than fall through to a zero hash.
	for _, p := range []AuthProtocol{AuthNone, 0, 99, -1} {
		if got, err := HashFunc(p); err == nil {
			t.Fatalf("HashFunc(%d) = %v, want error", p, got)
		} else if !strings.Contains(err.Error(), "no hash for auth protocol") {
			t.Fatalf("HashFunc(%d) error %q does not name the problem", p, err)
		}
	}
}

func TestMacLength(t *testing.T) {
	// RFC 3414 (MD5/SHA-1) and RFC 7860 (SHA-2) truncation lengths.
	want := map[AuthProtocol]int{
		AuthNone: 0, AuthMD5: 12, AuthSHA: 12, AuthSHA224: 16,
		AuthSHA256: 24, AuthSHA384: 32, AuthSHA512: 48,
	}
	for p, n := range want {
		if got := p.MacLength(); got != n {
			t.Fatalf("MacLength(%d) = %d, want %d", p, got, n)
		}
	}
	for _, p := range []AuthProtocol{0, 99, -1} {
		if got := p.MacLength(); got != 0 {
			t.Fatalf("MacLength(%d) = %d, want 0", p, got)
		}
	}
}

func TestKeyLength(t *testing.T) {
	// Localized auth key length is the full hash output length.
	want := map[AuthProtocol]int{
		AuthNone: 0, AuthMD5: 16, AuthSHA: 20, AuthSHA224: 28,
		AuthSHA256: 32, AuthSHA384: 48, AuthSHA512: 64,
	}
	for p, n := range want {
		if got := p.KeyLength(); got != n {
			t.Fatalf("KeyLength(%d) = %d, want %d", p, got, n)
		}
	}
	for _, p := range []AuthProtocol{0, 99, -1} {
		if got := p.KeyLength(); got != 0 {
			t.Fatalf("KeyLength(%d) = %d, want 0", p, got)
		}
	}
}

func TestPrivKeyLength(t *testing.T) {
	// DES/AES-128 use 16 bytes; AES-192 24; AES-256 32. The Reeder "C"
	// variants share the underlying key size with Blumenthal.
	want := map[PrivProtocol]int{
		PrivNone: 0, PrivDES: 16, PrivAES: 16, PrivAES192: 24,
		PrivAES256: 32, PrivAES192C: 24, PrivAES256C: 32,
	}
	for p, n := range want {
		if got := p.PrivKeyLength(); got != n {
			t.Fatalf("PrivKeyLength(%d) = %d, want %d", p, got, n)
		}
	}
	for _, p := range []PrivProtocol{0, 99, -1} {
		if got := p.PrivKeyLength(); got != 0 {
			t.Fatalf("PrivKeyLength(%d) = %d, want 0", p, got)
		}
	}
}

// TestParsedProtocolsHaveCompleteMetadata is the cross-check that catches a
// parser accepting a name the length tables do not know (or vice versa): a
// protocol that parses but has a zero MAC/key length would fail at runtime,
// far from the config line that caused it.
func TestParsedProtocolsHaveCompleteMetadata(t *testing.T) {
	authNames := []string{"md5", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"}
	for _, name := range authNames {
		p, err := ParseAuthProtocol(name)
		if err != nil {
			t.Fatalf("ParseAuthProtocol(%q): %v", name, err)
		}
		if p.KeyLength() == 0 {
			t.Fatalf("auth protocol %q parses but has no key length", name)
		}
		if p.MacLength() == 0 {
			t.Fatalf("auth protocol %q parses but has no MAC length", name)
		}
		if p.MacLength() > p.KeyLength() {
			// The digest truncation must never exceed the localized key;
			// that would make HMAC construction impossible.
			t.Fatalf("auth protocol %q MAC length %d exceeds key length %d", name, p.MacLength(), p.KeyLength())
		}
		if _, err := HashFunc(p); err != nil {
			t.Fatalf("auth protocol %q parses but has no hash: %v", name, err)
		}
	}

	privNames := []string{"des", "aes", "aes128", "aes192", "aes256", "aes192c", "aes256c"}
	for _, name := range privNames {
		p, err := ParsePrivProtocol(name)
		if err != nil {
			t.Fatalf("ParsePrivProtocol(%q): %v", name, err)
		}
		if p.PrivKeyLength() == 0 {
			t.Fatalf("priv protocol %q parses but has no key length", name)
		}
	}
}

// TestAliasesMatchCanonicalNames pins the aliases that config files in the
// wild rely on: "sha1" is SHA-1 and "aes128" is AES-128, not distinct
// protocols with distinct lengths.
func TestAliasesMatchCanonicalNames(t *testing.T) {
	sha, _ := ParseAuthProtocol("sha")
	sha1, _ := ParseAuthProtocol("sha1")
	if sha != sha1 {
		t.Fatalf("sha (%d) and sha1 (%d) are different protocols", sha, sha1)
	}
	aes, _ := ParsePrivProtocol("aes")
	aes128, _ := ParsePrivProtocol("aes128")
	if aes != aes128 {
		t.Fatalf("aes (%d) and aes128 (%d) are different protocols", aes, aes128)
	}
}
