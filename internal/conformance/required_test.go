package conformance

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// requiredEnv turns every environment-driven skip in this package into a
// failure. `make conformance-required` sets it for release runs.
//
// Without it, a host missing Docker (or pysnmp, or node) runs the matrix and
// reports success while only gosnmp actually executed — the strongest layer
// degrades silently, which is the one failure mode this package exists to
// prevent. Skips that represent a real vendor limitation
// (skipUnsupported / KindUnsupported) stay skips: the vendor genuinely cannot
// express the operation, and failing would be wrong.
const requiredEnv = "CONFORMANCE_REQUIRED"

// missingPeerFails reports whether an absent prerequisite must fail the run
// rather than skip it.
func missingPeerFails() bool { return os.Getenv(requiredEnv) != "" }

// skipOrFail is the single place that decides between "not available here"
// and "not available on a run that claims to be complete".
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if missingPeerFails() {
		t.Fatalf(format+" (%s is set: a complete run must not skip; run `make peers`)",
			append(args, requiredEnv)...)
	}
	t.Skipf(format, args...)
}

// TestMissingPeerFailsGate pins the decision itself in both directions.
func TestMissingPeerFailsGate(t *testing.T) {
	t.Setenv(requiredEnv, "")
	if missingPeerFails() {
		t.Fatal("missingPeerFails() is true with an empty environment")
	}
	t.Setenv(requiredEnv, "1")
	if !missingPeerFails() {
		t.Fatalf("missingPeerFails() ignores %s: `make conformance-required` would pass on a host where every peer skipped", requiredEnv)
	}
}

// TestMissingRuntimeSkipsInsteadOfFailing pins the companion rule: a peer
// whose runtime lives on PATH must report itself unavailable when that
// runtime is gone, instead of claiming to be available and then failing every
// scenario as an adapter error (found by running the gate on a trimmed PATH).
func TestMissingRuntimeSkipsInsteadOfFailing(t *testing.T) {
	p := newExecPeer("synthetic", "synthetic runtime", "snmp-shield-no-such-runtime",
		[]string{"peer_netsnmp.py"}, "")
	reason := p.Unavailable()
	if reason == "" {
		t.Fatal("a peer whose runtime is absent reported itself available: the scenarios would fail as adapter errors instead of skipping")
	}
	t.Logf("skip reason: %s", reason)
}

// TestNoSkipBypassesRequiredGate is the tripwire for the tripwire: it fails
// when a skip site is added that does not route through skipOrFail, because
// such a skip silently survives a required run. Vendor limitations are the
// documented exception (they are not environment failures).
//
// The check is a source scan on purpose: a behavioural test can only visit
// the skip sites that exist today, while the risk is the one someone adds
// tomorrow.
func TestNoSkipBypassesRequiredGate(t *testing.T) {
	const helperFile = "required_test.go" // skipOrFail itself
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("scan package: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || name == helperFile {
			continue
		}
		raw, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "t.Skip") {
				continue
			}
			// The only sanctioned direct skip: a vendor cannot express
			// the operation, which no toolchain install can fix.
			if strings.Contains(line, "vendor does not support this operation") {
				continue
			}
			offenders = append(offenders, name+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these skips bypass skipOrFail(), so a required run still passes with a missing toolchain:\n  %s\nRoute them through skipOrFail (environment) or skipUnsupported (vendor limitation).",
			strings.Join(offenders, "\n  "))
	}
}
