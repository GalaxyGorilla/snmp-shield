// Package tunnel: transport layer — DTLS over UDP (primary) and TLS over
// TCP (alternative). Both present the same connection interface.
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v3"
)

// Dialer dials a tunnel endpoint.
type Dialer struct {
	Mode        string // "dtls" or "tls"
	RemoteAddr  string // tunnel endpoint address to dial
	PSK         []byte
	PSKIdentity []byte
	// PskCiphersuites selects the DTLS 1.2 PSK cipher suites, most
	// preferred first ("aes128-ccm-8", "aes256-ccm-8", "aes128-ccm",
	// "aes128-gcm", "aes128-cbc" or full RFC names). Empty = default
	// (aes128-ccm-8). Only used in PSK mode.
	PskCiphersuites []string
	CAFile          string
	CertFile        string
	KeyFile         string
	ServerName      string
	Insecure        bool
	Timeout         time.Duration
}

// tlsConfig builds a mutual-TLS *tls.Config for the "tls" mode.
func (d *Dialer) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         d.ServerName,
		InsecureSkipVerify: d.Insecure, //nolint:gosec // config-controlled
		MinVersion:         tls.VersionTLS12,
	}
	if d.CertFile != "" && d.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if d.CAFile != "" {
		pem, err := os.ReadFile(d.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs in %s", d.CAFile)
		}
		cfg.RootCAs = pool
	}
	if !d.Insecure && cfg.RootCAs == nil && d.ServerName == "" {
		return nil, errors.New("tls: need server_name, ca_file, or insecure_skip_verify")
	}
	return cfg, nil
}

// dtlsConfig builds the pion/dtls.Config for the "dtls" mode, PSK or
// certificate-based.
func (d *Dialer) dtlsConfig() (*dtls.Config, error) {
	if len(d.PSK) > 0 {
		suites, err := PskCipherSuiteIDs(d.PskCiphersuites)
		if err != nil {
			return nil, err
		}
		return &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				return d.PSK, nil
			},
			PSKIdentityHint:      d.PSKIdentity,
			CipherSuites:         suites,
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		}, nil
	}
	tc, err := d.tlsConfig()
	if err != nil {
		return nil, err
	}
	cfg := &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ServerName:           d.ServerName,
	}
	if len(tc.Certificates) > 0 {
		cfg.Certificates = tc.Certificates
	}
	if tc.RootCAs != nil {
		cfg.RootCAs = tc.RootCAs
	}
	if tc.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// Dial connects to the tunnel endpoint. For "dtls" mode the network is
// udp; for "tls" mode, tcp. It blocks until the (D)TLS handshake
// completes or ctx/timeout expires.
func (d *Dialer) Dial(ctx context.Context, raddr string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch d.Mode {
	case "dtls":
		dcfg, err := d.dtlsConfig()
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveUDPAddr("udp", raddr)
		if err != nil {
			return nil, fmt.Errorf("resolve tunnel addr: %w", err)
		}
		// dtls.Dial is blocking with its own handshake timeout handling;
		// wrap with the ctx via a goroutine for cancellation support.
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			conn, derr := dtls.Dial("udp", addr, dcfg)
			ch <- result{conn, derr}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, fmt.Errorf("dtls dial: %w", r.err)
			}
			// DTLS preserves record boundaries; wrap into a byte stream.
			return newStreamConn(r.conn, true), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(timeout):
			return nil, fmt.Errorf("dtls dial: timeout after %s", timeout)
		}
	case "tls":
		tcfg, err := d.tlsConfig()
		if err != nil {
			return nil, err
		}
		nd := net.Dialer{Timeout: timeout}
		raw, err := nd.DialContext(ctx, "tcp", raddr)
		if err != nil {
			return nil, fmt.Errorf("tcp dial: %w", err)
		}
		if tcfg.ServerName == "" {
			host, _, splitErr := net.SplitHostPort(raddr)
			if splitErr == nil {
				tcfg.ServerName = host
			}
		}
		conn := tls.Client(raw, tcfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unknown tunnel mode %q", d.Mode)
	}
}
