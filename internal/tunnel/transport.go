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
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// Dialer dials a tunnel endpoint. When RemoteAddrs lists more than one
// endpoint, Dial walks them (HA failover, sticky: the last-known-good
// endpoint is tried first on every dial).
type Dialer struct {
	Mode       string // "dtls" or "tls"
	RemoteAddr string // tunnel endpoint address to dial (single-endpoint mode)
	// RemoteAddrs lists the tunnel endpoints, most preferred first. When
	// set, Dial ignores RemoteAddr and walks the list starting at the
	// last-known-good index. The first success pins the index.
	RemoteAddrs []string
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

	// Sticky failover state: index into RemoteAddrs of the last
	// known-good endpoint. Guarded by failMu.
	failMu  sync.Mutex
	failIdx int
}

// currentIdx returns the sticky failover index (for endpoint-change
// detection by the session layer).
func (d *Dialer) currentIdx() int {
	d.failMu.Lock()
	defer d.failMu.Unlock()
	return d.failIdx
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

// dtlsClientOptions builds the pion/dtls client options for the "dtls"
// mode, PSK or certificate-based.
func (d *Dialer) dtlsClientOptions() ([]dtls.ClientOption, error) {
	if len(d.PSK) > 0 {
		suites, err := PskCipherSuiteIDs(d.PskCiphersuites)
		if err != nil {
			return nil, err
		}
		// pion v3.1.4 normalizes an empty PSK identity hint to nil
		// (WithPSKIdentityHint defensively copies, toConfig drops
		// len==0), which makes the client's ClientKeyExchange marshal
		// fail (nil identity, no public key) and the handshake hang
		// forever. Keep the pre-3.1.4 wire semantics: an empty
		// configured identity becomes a 1-byte placeholder so the hint
		// stays non-nil. The peer's PSK callback ignores the hint.
		identity := d.PSKIdentity
		if len(identity) == 0 {
			identity = []byte{0}
		}
		return []dtls.ClientOption{
			dtls.WithPSK(func(hint []byte) ([]byte, error) {
				return d.PSK, nil
			}),
			dtls.WithPSKIdentityHint(identity),
			dtls.WithCipherSuites(suites...),
			dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		}, nil
	}
	tc, err := d.tlsConfig()
	if err != nil {
		return nil, err
	}
	var opts []dtls.ClientOption
	opts = append(opts, dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret))
	if d.ServerName != "" {
		opts = append(opts, dtls.WithServerName(d.ServerName))
	}
	if len(tc.Certificates) > 0 {
		opts = append(opts, dtls.WithCertificates(tc.Certificates...))
	}
	if tc.RootCAs != nil {
		opts = append(opts, dtls.WithRootCAs(tc.RootCAs))
	}
	if tc.InsecureSkipVerify {
		opts = append(opts, dtls.WithInsecureSkipVerify(true))
	}
	return opts, nil
}

// Dial connects to the tunnel endpoint. For "dtls" mode the network is
// udp; for "tls" mode, tcp. It blocks until the (D)TLS handshake
// completes or ctx/timeout expires.
//
// When RemoteAddrs is set, raddr is ignored and Dial walks the endpoint
// list starting at the last-known-good index (sticky HA failover): each
// endpoint gets the full timeout, and the first success pins the index.
func (d *Dialer) Dial(ctx context.Context, raddr string) (net.Conn, error) {
	if len(d.RemoteAddrs) > 0 {
		return d.dialFailover(ctx)
	}
	return d.dialOne(ctx, raddr)
}

// dialFailover walks RemoteAddrs starting at the sticky index.
func (d *Dialer) dialFailover(ctx context.Context) (net.Conn, error) {
	d.failMu.Lock()
	start := d.failIdx
	d.failMu.Unlock()
	n := len(d.RemoteAddrs)
	var lastErr error
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		addr := d.RemoteAddrs[idx]
		conn, err := d.dialOne(ctx, addr)
		if err == nil {
			d.failMu.Lock()
			d.failIdx = idx
			d.failMu.Unlock()
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("dial: no tunnel endpoints configured")
	}
	return nil, lastErr
}

// dialOne dials a single endpoint (the pre-existing single-endpoint path).
func (d *Dialer) dialOne(ctx context.Context, raddr string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch d.Mode {
	case "dtls":
		copts, err := d.dtlsClientOptions()
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveUDPAddr("udp", raddr)
		if err != nil {
			return nil, fmt.Errorf("resolve tunnel addr: %w", err)
		}
		// dtls.DialWithOptions does NOT run the handshake: it returns
		// instantly and the handshake completes lazily on first
		// Read/Write. Run it eagerly here (bounded by ctx/timeout) so
		// dial errors surface to the caller — the HA failover walk needs
		// per-endpoint failures to move on to the next endpoint.
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			dconn, derr := dtls.DialWithOptions("udp", addr, copts...)
			if derr == nil {
				hctx, hcancel := context.WithTimeout(ctx, timeout)
				defer hcancel()
				derr = dconn.HandshakeContext(hctx)
			}
			if derr != nil {
				if dconn != nil {
					_ = dconn.Close()
				}
				ch <- result{nil, derr}
				return
			}
			ch <- result{dconn, nil}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, fmt.Errorf("dtls dial: %w", r.err)
			}
			// DTLS preserves record boundaries; wrap into a byte stream.
			return newStreamConn(r.conn.(*dtls.Conn), true), nil
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
