// Command smoke-client performs one gosnmp GET against 127.0.0.1:<port>
// (the manager proxy's clear listener) and prints the result. Used by
// scripts/smoke-cli.sh.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: smoke-client <port>")
		os.Exit(2)
	}
	g := &gosnmp.GoSNMP{
		Target:    "127.0.0.1",
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   2,
		MaxOids:   1,
		Transport: "udp",
	}
	// parse port
	fmt.Sscanf(os.Args[1], "%d", &g.Port)

	if err := g.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer g.Conn.Close()

	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "get: %v\n", err)
		os.Exit(1)
	}
	if len(result.Variables) != 1 {
		fmt.Fprintf(os.Stderr, "want 1 varbind, got %d\n", len(result.Variables))
		os.Exit(1)
	}
	v := result.Variables[0]
	val, ok := v.Value.([]byte)
	if !ok {
		fmt.Fprintf(os.Stderr, "unexpected varbind type %v\n", v.Type)
		os.Exit(1)
	}
	fmt.Printf("sysDescr.0 = %q\n", string(val))
}
