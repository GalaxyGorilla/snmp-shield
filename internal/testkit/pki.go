package testkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PKI is a throwaway certificate set for the TLS/DTLS legs.
type PKI struct {
	Dir       string
	CAFile    string
	ServerCrt string
	ServerKey string
	ClientCrt string
	ClientKey string

	// CACert is the parsed CA, for tests that need to build their own
	// tls.Config rather than point a dialer at files.
	CACert *x509.Certificate
}

// NewPKI writes a CA, a server certificate (SANs: localhost, 127.0.0.1,
// ::1) and a client certificate into a temp dir.
//
// The SANs matter: net-snmp's TSM client only matches DNS names, and a
// certificate without 127.0.0.1 fails loopback tests for reasons that look
// like a protocol bug. Server and client are separate certificates with
// separate EKUs, because a server-only certificate presented as a client is
// rejected by RequireAndVerifyClientCert sinks.
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testkit: ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "snmp-shield test CA", Organization: []string{"testkit"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("testkit: ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("testkit: parse ca: %v", err)
	}

	p := &PKI{
		Dir:       dir,
		CAFile:    filepath.Join(dir, "ca.pem"),
		ServerCrt: filepath.Join(dir, "server.pem"),
		ServerKey: filepath.Join(dir, "server-key.pem"),
		ClientCrt: filepath.Join(dir, "client.pem"),
		ClientKey: filepath.Join(dir, "client-key.pem"),
		CACert:    caCert,
	}
	writePEM(t, p.CAFile, "CERTIFICATE", caDER)
	issueLeaf(t, caCert, caKey, p.ServerCrt, p.ServerKey,
		"snmp-shield-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"localhost", "127.0.0.1", "::1"})
	issueLeaf(t, caCert, caKey, p.ClientCrt, p.ClientKey,
		"snmp-shield-manager", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		[]string{"localhost", "127.0.0.1"})
	return p
}

func issueLeaf(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, crtPath, keyPath, cn string, eku []x509.ExtKeyUsage, dns []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testkit: leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"testkit"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("testkit: leaf cert: %v", err)
	}
	writePEM(t, crtPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("testkit: leaf key marshal: %v", err)
	}
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
}

func writePEM(t testing.TB, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("testkit: create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("testkit: write %s: %v", path, err)
	}
}

// LoopbackAddrs returns "127.0.0.1:port" and "[::1]:port" forms, which
// some tests need because the access allow-list treats them as different
// clients.
func LoopbackAddrs(addr string) []net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return []net.IP{ip}
}
