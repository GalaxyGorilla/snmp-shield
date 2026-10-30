// Package securitylevel is the leaf package that owns the SNMPv3 USM
// protocol vocabulary: the authentication and privacy protocol enums,
// their config-string parsers and their wire/key sizes.
//
// It exists as a leaf so that config validation can reject a typo like
// auth_protocol: "shaa" before the process starts, without importing the
// usm package (which imports config). internal/usm re-exports these types
// as aliases, so the protocol constants keep their familiar names.
package securitylevel

import (
	"crypto"
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
	PrivAES     PrivProtocol = 3 // AES-128 (CFB)
	PrivAES192  PrivProtocol = 4 // Blumenthal extension
	PrivAES256  PrivProtocol = 5 // Blumenthal extension
	PrivAES192C PrivProtocol = 6 // Reeder extension
	PrivAES256C PrivProtocol = 7 // Reeder extension
)

// HashFunc maps the protocol to its crypto.Hash (MD5/SHA1/SHA-2 family).
func HashFunc(a AuthProtocol) (crypto.Hash, error) {
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

// ParseAuthProtocol maps config strings to AuthProtocol. An empty string
// and "none" both mean no authentication.
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
		return 0, fmt.Errorf("usm: unknown auth protocol %q (use none, md5, sha, sha224, sha256, sha384 or sha512)", s)
	}
}

// ParsePrivProtocol maps config strings to PrivProtocol. An empty string
// and "none" both mean no privacy.
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
		return 0, fmt.Errorf("usm: unknown privacy protocol %q (use none, des, aes, aes192, aes256, aes192c or aes256c)", s)
	}
}
