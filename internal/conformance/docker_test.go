package conformance

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file holds the Docker-backed TSM client, not a test: RFC 6353 is not
// expressible in the vendor-neutral peer contract (the target is a `dtls:`
// URL plus a certificate identity, and net-snmp refuses an IP address), so
// the TSM scenarios drive the container directly instead of forcing the
// contract to grow a transport-shaped hole.

// requireDockerNetSNMP skips unless a usable Docker daemon and the peer image
// are present. Like every other peer: a missing toolchain is a skip, never a
// failure (this repository has no CI).
func requireDockerNetSNMP(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		skipOrFail(t, "docker not installed — the third-party TSM client needs it (see CONFORMANCE.md)")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		skipOrFail(t, "docker daemon unavailable (%s) — start Docker and run `make peers`", firstLine(string(out)))
	}
	if err := exec.Command("docker", "image", "inspect", dockerNetSNMPImage).Run(); err != nil {
		skipOrFail(t, "image %s missing — run `make peers` to build it", dockerNetSNMPImage)
	}
}

// netsnmpVersion asks the container which net-snmp it carries, for failure
// output (a version-dependent divergence must not look like our bug).
func netsnmpVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", dockerNetSNMPImage, "snmpget", "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(firstLine(strings.TrimSpace(string(out))))
}

// tsmClientHome prepares a net-snmp client identity directory and returns
// its path, ready to be mounted at /home/peer.
//
// net-snmp keeps TLS material in $HOME/.snmp/tls/{ca-certs,certs,private} and
// keys its trust store by SHA-256 fingerprint, so both fingerprints have to
// be written into snmp.conf. `clientCert` is deprecated in 5.9 (it warns) but
// it is what actually feeds the client-identity lookup.
func tsmClientHome(t *testing.T, crtPath, keyPath, caPath string) string {
	t.Helper()
	home := t.TempDir()
	for _, dir := range []string{"ca-certs", "certs", "private"} {
		if err := os.MkdirAll(filepath.Join(home, ".snmp", "tls", dir), 0o755); err != nil {
			t.Fatalf("conformance: tsm client home: %v", err)
		}
	}
	copyFile(t, crtPath, filepath.Join(home, ".snmp", "tls", "certs", "client.crt"))
	copyFile(t, keyPath, filepath.Join(home, ".snmp", "tls", "private", "client.key"))
	if err := os.Chmod(filepath.Join(home, ".snmp", "tls", "private", "client.key"), 0o600); err != nil {
		t.Fatalf("conformance: tsm client key mode: %v", err)
	}
	copyFile(t, caPath, filepath.Join(home, ".snmp", "tls", "ca-certs", "ca.crt"))

	conf := fmt.Sprintf("clientCert %s\ntrustCert %s\n",
		certFingerprint(t, crtPath), certFingerprint(t, caPath))
	if err := os.WriteFile(filepath.Join(home, ".snmp", "snmp.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("conformance: tsm client config: %v", err)
	}
	return home
}

// certFingerprint is the net-snmp trust-store key: SHA-256 of the DER cert,
// uppercase hex with colons (what `openssl x509 -fingerprint -sha256` prints).
func certFingerprint(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("conformance: read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("conformance: %s is not PEM", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("conformance: parse %s: %v", path, err)
	}
	sum := sha256.Sum256(block.Bytes)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// runTSMClient executes one net-snmp command inside the peer container with
// the given client identity mounted. ok reports whether the command exited 0;
// out is the combined output, which is what a failing scenario prints.
func runTSMClient(t *testing.T, home string, args ...string) (string, bool) {
	t.Helper()
	full := append([]string{"run", "--rm", "-v", home + ":/home/peer", dockerNetSNMPImage}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	return string(out), err == nil
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("conformance: read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatalf("conformance: write %s: %v", dst, err)
	}
}
