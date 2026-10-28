// Package conformance drives snmp-shield through the real command-line
// binary with third-party SNMP stacks as peers.
//
// The point is independence. Our own tests are written against our own
// encoders, so they can only prove self-consistency: if we mis-encode
// msgMaxSize the same way in the encoder and the decoder, every test in
// internal/* still passes. A vendor stack has no such symmetry with us, and
// the whole class of bugs that the project has actually hit (non-minimal
// INTEGERs, double-wrapped varbind lists, missing reportable flags, TSM
// echo rules) was found by one.
//
// Rules for this package:
//
//   - Peers are never adapted to us. When two vendors disagree, that is a
//     finding for CONFORMANCE.md, not a compiler error to work around.
//   - Scenarios assert on the contract (ok / error_kind / varbinds), never
//     on a vendor's prose.
//   - A missing toolchain skips, it does not fail: this repository has no CI
//     and must stay green on a machine with no Python venv.
package conformance

import (
	"context"
)

// Verb is one SNMP operation a peer can perform.
type Verb string

const (
	VerbGet     Verb = "get"
	VerbGetNext Verb = "getnext"
	VerbGetBulk Verb = "getbulk"
	VerbWalk    Verb = "walk"
	VerbSet     Verb = "set"
	VerbTrap    Verb = "trap"
	VerbInform  Verb = "inform"
)

// Request is a vendor-neutral description of one operation.
type Request struct {
	Verb Verb

	// Version is "1", "2c" or "3".
	Version string
	// Level is the USM security level: noauthnopriv, authnopriv, authpriv.
	// Empty derives it from the credentials.
	Level string

	Community string
	User      string
	Auth      string
	Priv      string

	AuthProto string // sha (default), md5, sha256, ...
	PrivProto string // aes (default), des, ...

	// Target is host:port.
	Target string

	OIDs     []string
	Varbinds []string // oid=TYPE:value, for SET and notifications

	// v1 notifications only: SNMPv1 has no snmpTrapOID.0 varbind, so the
	// notification is described by enterprise + generic + specific. When
	// Enterprise is empty it is derived from the last OID arc
	// (enterprise = OID minus last arc, specific = last arc, generic = 6),
	// which is the RFC 2576 translation shape.
	Enterprise string
	AgentAddr  string
	Generic    int
	Specific   int

	Timeout float64 // seconds
	Retries int

	MaxRepetitions int
}

// Varbind is one decoded answer.
type Varbind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Result is the outcome of an operation. ErrorKind is the contract; Error is
// vendor prose that exists for humans and must never be asserted on.
type Result struct {
	OK        bool      `json:"ok"`
	ErrorKind string    `json:"error_kind"`
	Error     string    `json:"error"`
	Varbinds  []Varbind `json:"varbinds"`
}

// ErrorKind values the adapters agree on.
const (
	KindTimeout    = "timeout"
	KindAuth       = "auth"
	KindDecrypt    = "decrypt"
	KindSecLevel   = "security-level"
	KindTimeliness = "timeliness"
	KindNoEngine   = "engine-discovery"
	KindStatus     = "status"
	KindIndication = "indication"
	KindUnavail    = "unavailable"
	KindUsage      = "usage"
	// KindUnsupported says the vendor stack cannot express this operation at
	// all (SNMPv1 notifications in some libraries, for example). Scenarios
	// skip instead of failing: a missing vendor feature is not our bug.
	KindUnsupported = "unsupported"
)

// Peer is one third-party SNMP stack.
type Peer interface {
	// Name is the adapter's short name, used as the subtest name.
	Name() string
	// Stack describes the implementation and version, for failure output.
	Stack() string
	// Unavailable explains why the peer cannot run here, or returns "".
	Unavailable() string
	// Run performs one operation. It returns an error only when the adapter
	// itself failed (crash, unparseable output); a refusal by the network
	// or the peer is a Result.
	Run(ctx context.Context, req Request) (Result, error)
}

// AllPeers returns every configured peer. Unavailable ones are included so
// the matrix is visible in `go test -v` output.
func AllPeers() []Peer {
	return []Peer{
		newGoSnmpPeer(),
		newExecPeer("netsnmp", "net-snmp CLI (snmpget/snmpset)", "python3",
			[]string{"peer_netsnmp.py"}, "snmpget"),
		newExecPeer("pysnmp", "pysnmp (pure Python)", ".venv/bin/python",
			[]string{"peer_pysnmp.py"}, ""),
		newExecPeer("node", "node net-snmp (JavaScript)", "node",
			[]string{"peer_node.js"}, ""),
		// Same adapter, current net-snmp: the host CLI is Apple's 5.6.2.1.
		// A container peer needs the fixture to bind a routable address,
		// which the scenarios handle through peerFront.
		newDockerNetSNMPPeer(),
	}
}
