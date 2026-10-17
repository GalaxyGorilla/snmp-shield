// Package tunnel: listener (server) side for DTLS/UDP and TLS/TCP.
package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/pion/dtls/v3"
)

// ListenerConfig mirrors Dialer for the server side.
type ListenerConfig struct {
	Mode        string // "dtls" or "tls"
	PSK         []byte
	PSKIdentity []byte
	// PskCiphersuites selects the DTLS 1.2 PSK cipher suites in server
	// preference order ("aes128-ccm-8", "aes256-ccm-8", "aes128-ccm",
	// "aes128-gcm", "aes128-cbc" or full RFC names). Empty = default
	// (aes128-ccm-8). Only used in PSK mode. Must overlap with the
	// client's list or the handshake fails.
	PskCiphersuites []string
	CAFile          string
	CertFile        string
	KeyFile         string
	Insecure        bool // DTLS cert mode: skip client-cert verification
}

// Listen binds the tunnel listener at laddr. The returned Listener is a
// net.Adapter-compatible net.Listener (Accept/Close/Addr).
func Listen(laddr string, cfg ListenerConfig) (net.Listener, error) {
	switch cfg.Mode {
	case "dtls":
		sopts, err := dtlsServerOptions(cfg)
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, fmt.Errorf("resolve tunnel listen addr: %w", err)
		}
		l, err := dtls.ListenWithOptions("udp", addr, sopts...)
		if err != nil {
			return nil, fmt.Errorf("dtls listen: %w", err)
		}
		return &streamListener{Listener: l}, nil
	case "tls":
		tcfg, err := tlsServerConfig(cfg)
		if err != nil {
			return nil, err
		}
		l, err := tls.Listen("tcp", laddr, tcfg)
		if err != nil {
			return nil, fmt.Errorf("tls listen: %w", err)
		}
		return l, nil
	default:
		return nil, fmt.Errorf("unknown tunnel mode %q", cfg.Mode)
	}
}

// dtlsServerOptions builds the pion/dtls server options, PSK or
// certificate-based.
func dtlsServerOptions(cfg ListenerConfig) ([]dtls.ServerOption, error) {
	if len(cfg.PSK) > 0 {
		suites, err := PskCipherSuiteIDs(cfg.PskCiphersuites)
		if err != nil {
			return nil, err
		}
		// Mirror the client-side fix: pion v3.1.4 normalizes an empty
		// PSK identity hint to nil, and a server with a nil hint omits
		// the ServerKeyExchange entirely (fine per RFC 4279, but the
		// placeholder keeps the v3.0.10 wire shape and exercises the
		// same code path on both sides). The PSK callback ignores the
		// hint value.
		identity := cfg.PSKIdentity
		if len(identity) == 0 {
			identity = []byte{0}
		}
		return []dtls.ServerOption{
			dtls.WithPSK(func(hint []byte) ([]byte, error) {
				return cfg.PSK, nil
			}),
			dtls.WithPSKIdentityHint(identity),
			dtls.WithCipherSuites(suites...),
			dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		}, nil
	}
	tcfg, err := tlsServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	var opts []dtls.ServerOption
	opts = append(opts, dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret))
	if len(tcfg.Certificates) > 0 {
		opts = append(opts, dtls.WithCertificates(tcfg.Certificates...))
	}
	if tcfg.ClientCAs != nil {
		opts = append(opts, dtls.WithClientCAs(tcfg.ClientCAs), dtls.WithClientAuth(dtls.RequireAndVerifyClientCert))
	}
	if cfg.Insecure {
		opts = append(opts, dtls.WithClientAuth(dtls.NoClientCert), dtls.WithInsecureSkipVerify(true))
	}
	return opts, nil
}

// tlsServerConfig builds the crypto/tls server config.
func tlsServerConfig(cfg ListenerConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("tls server needs cert_file and key_file")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tcfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs in %s", cfg.CAFile)
		}
		tcfg.ClientCAs = pool
		tcfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tcfg, nil
}

// streamListener wraps a DTLS listener so accepted conns are stream-
// buffered (DTLS preserves record boundaries per Read).
type streamListener struct {
	net.Listener
}

func (s *streamListener) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newStreamConn(c, true), nil
}

// ListenRaw binds a raw-mode DTLS listener at laddr: accepted conns
// preserve DTLS record boundaries per Read with NO stream buffering and
// no frame layer. This is the RFC 6353 (SNMP-over-DTLS) front leg: one
// SNMP datagram equals one DTLS record. Cert material semantics match
// Listen (PSK is not part of the TSM profile). TLS/TCP is not supported
// in raw mode: TCP is a byte stream, so the one-record-one-datagram
// property only holds for DTLS.
func ListenRaw(laddr string, cfg ListenerConfig) (net.Listener, error) {
	if cfg.Mode != "dtls" {
		return nil, fmt.Errorf("raw listen mode must be dtls, got %q (TLS/TCP has no record boundaries)", cfg.Mode)
	}
	sopts, err := dtlsServerOptions(cfg)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("resolve raw listen addr: %w", err)
	}
	l, err := dtls.ListenWithOptions("udp", addr, sopts...)
	if err != nil {
		return nil, fmt.Errorf("dtls listen: %w", err)
	}
	return &rawListener{Listener: l}, nil
}

// rawListener hands out accepted conns as-is: (D)TLS record boundaries
// per Read (one SNMP datagram per Read), peer certs reachable via
// PeerCerts for TSM identity mapping.
type rawListener struct {
	net.Listener
}

func (r *rawListener) Accept() (net.Conn, error) {
	return r.Listener.Accept()
}
