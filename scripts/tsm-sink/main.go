// Command tsm-sink is a raw DTLS (RFC 6353) trap sink used by
// scripts/interop-gateway-tsm.sh. It listens with the given certificate
// material, accepts one DTLS session, reads raw SNMP datagrams (one
// record per datagram — no frame layer) and appends them to a file so
// the test can check delivery. Validating the wrapped notification's
// crypto is covered by internal/tsm/gateway_test.go.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: tsm-sink <listen-port> <cert.pem> <key.pem> <out-file> [ca.pem]\n")
		os.Exit(2)
	}
	port := os.Args[1]
	// ca.pem is optional: when given, client certificates are required and
	// verified against it. Without it, any client may connect (the wrapped
	// notification's crypto is validated by internal/tsm/gateway_test.go).
	lcfg := tunnel.ListenerConfig{
		Mode:     "dtls",
		CertFile: os.Args[2],
		KeyFile:  os.Args[3],
	}
	if len(os.Args) > 5 {
		lcfg.CAFile = os.Args[5]
	}
	l, err := tunnel.ListenRaw(net.JoinHostPort("127.0.0.1", port), lcfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tsm-sink: listen: %v\n", err)
		os.Exit(1)
	}
	defer l.Close()
	fmt.Fprintf(os.Stderr, "tsm-sink: listening on %s\n", l.Addr())

	_ = os.WriteFile(os.Args[4], []byte{}, 0o600)

	c, err := l.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tsm-sink: accept: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	f, err := os.OpenFile(os.Args[4], os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tsm-sink: open out: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	buf := make([]byte, 65536)
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				fmt.Fprintf(os.Stderr, "tsm-sink: write: %v\n", werr)
				os.Exit(1)
			}
		}
		if err != nil {
			if err == io.EOF || os.IsTimeout(err) {
				return
			}
			fmt.Fprintf(os.Stderr, "tsm-sink: read: %v\n", err)
			return
		}
	}
}
