// A local throwaway PKI for tunnel tests.
//
// It deliberately does not use internal/testkit: testkit imports this
// package (for the in-memory pipe), so importing it from a `package tunnel`
// test would create a cycle. The code is the same shape as testkit's PKI —
// one CA, a server leaf with loopback SANs, and a separate client leaf —
// kept here so the unexported tlsConfig/tlsServerConfig paths stay testable.
package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testPKI struct {
	CAFile    string
	ServerCrt string
	ServerKey string
	ClientCrt string
	ClientKey string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunnel test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	p := &testPKI{
		CAFile:    filepath.Join(dir, "ca.pem"),
		ServerCrt: filepath.Join(dir, "server.pem"),
		ServerKey: filepath.Join(dir, "server-key.pem"),
		ClientCrt: filepath.Join(dir, "client.pem"),
		ClientKey: filepath.Join(dir, "client-key.pem"),
	}
	writeTestPEM(t, p.CAFile, "CERTIFICATE", caDER)
	issueTestLeaf(t, caCert, caKey, p.ServerCrt, p.ServerKey,
		"snmp-shield-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"localhost", "127.0.0.1", "::1"})
	issueTestLeaf(t, caCert, caKey, p.ClientCrt, p.ClientKey,
		"snmp-shield-manager", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		[]string{"localhost", "127.0.0.1"})
	return p
}

func issueTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, crtPath, keyPath, cn string, eku []x509.ExtKeyUsage, dns []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	writeTestPEM(t, crtPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("leaf key marshal: %v", err)
	}
	writeTestPEM(t, keyPath, "EC PRIVATE KEY", keyDER)
}

func writeTestPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
