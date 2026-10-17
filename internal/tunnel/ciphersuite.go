package tunnel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pion/dtls/v3"
)

// pskCiphersuiteIDs maps operator-facing names (and the full RFC names
// as aliases) to the pion/dtls PSK cipher suite IDs. The tunnel is
// DTLS 1.2, so only the suites pion implements are selectable:
//
//	aes128-ccm-8  TLS_PSK_WITH_AES_128_CCM_8       (default, 128-bit tag)
//	aes256-ccm-8  TLS_PSK_WITH_AES_256_CCM_8       (256-bit key)
//	aes128-ccm    TLS_PSK_WITH_AES_128_CCM         (full-length tag)
//	aes128-gcm    TLS_PSK_WITH_AES_128_GCM_SHA256
//	aes128-cbc    TLS_PSK_WITH_AES_128_CBC_SHA256  (legacy, avoid)
var pskCiphersuiteIDs = map[string]dtls.CipherSuiteID{
	"aes128-ccm-8": dtls.TLS_PSK_WITH_AES_128_CCM_8,
	"aes256-ccm-8": dtls.TLS_PSK_WITH_AES_256_CCM_8,
	"aes128-ccm":   dtls.TLS_PSK_WITH_AES_128_CCM,
	"aes128-gcm":   dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	"aes128-cbc":   dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
	// Full RFC cipher suite names are accepted as aliases.
	"TLS_PSK_WITH_AES_128_CCM_8":      dtls.TLS_PSK_WITH_AES_128_CCM_8,
	"TLS_PSK_WITH_AES_256_CCM_8":      dtls.TLS_PSK_WITH_AES_256_CCM_8,
	"TLS_PSK_WITH_AES_128_CCM":        dtls.TLS_PSK_WITH_AES_128_CCM,
	"TLS_PSK_WITH_AES_128_GCM_SHA256": dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	"TLS_PSK_WITH_AES_128_CBC_SHA256": dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
}

// DefaultPskCiphersuite is used when no ciphersuite is configured.
const DefaultPskCiphersuite = "aes128-ccm-8"

// PskCiphersuiteNames lists the supported short names, sorted (for
// docs and error messages).
func PskCiphersuiteNames() []string {
	names := make([]string, 0, len(pskCiphersuiteIDs))
	for n := range pskCiphersuiteIDs {
		if !strings.HasPrefix(n, "TLS_") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// PskCipherSuiteIDs resolves configured ciphersuite names (short form
// like "aes256-ccm-8" or full RFC form) into pion/dtls IDs, preserving
// order: the first entry is the client's most preferred suite. An
// empty/nil list yields the default suite, keeping existing deployments
// unchanged.
func PskCipherSuiteIDs(names []string) ([]dtls.CipherSuiteID, error) {
	if len(names) == 0 {
		return []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8}, nil
	}
	ids := make([]dtls.CipherSuiteID, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		id, ok := pskCiphersuiteIDs[n]
		if !ok {
			return nil, fmt.Errorf("unknown psk ciphersuite %q (supported: %s)",
				n, strings.Join(PskCiphersuiteNames(), ", "))
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8}, nil
	}
	return ids, nil
}

// ValidatePskCiphersuites checks that every configured name is
// supported. An empty list is valid (the default applies).
func ValidatePskCiphersuites(names []string) error {
	_, err := PskCipherSuiteIDs(names)
	return err
}
