package conformance

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// eachPeer runs the scenario function once per available peer, as a subtest.
// The skip reason is printed so a green run still shows what was not covered.
func eachPeer(t *testing.T, fn func(t *testing.T, p Peer)) {
	t.Helper()
	for _, p := range AllPeers() {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			if reason := p.Unavailable(); reason != "" {
				skipOrFail(t, "%s unavailable: %s", p.Stack(), reason)
			}
			t.Logf("peer: %s", p.Stack())
			fn(t, p)
		})
	}
}

// mustRun runs one operation and fails the test when the adapter itself
// breaks. Vendor-level refusals come back as a Result with OK=false.
func mustRun(t *testing.T, p Peer, req Request) Result {
	t.Helper()
	if req.Timeout == 0 {
		req.Timeout = 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := p.Run(ctx, req)
	if err != nil {
		t.Fatalf("%s: adapter failure: %v", p.Name(), err)
	}
	if res.ErrorKind == KindUsage {
		t.Fatalf("%s: scenario bug (adapter usage error): %s", p.Name(), res.Error)
	}
	// Summarize long varbind lists: a walk over a real MIB returns hundreds
	// of rows, and a single Logf of all of them buries every other line of
	// the test log (a peer that walked the whole tree instead of the
	// requested subtree produced a 650 KB log line). The count is always
	// printed, so a truncation cannot hide "it returned far too much".
	t.Logf("%s %s %s -> ok=%v kind=%q varbinds=%s", p.Name(), req.Verb,
		strings.Join(req.OIDs, ","), res.OK, res.ErrorKind, summarizeVarbinds(res.Varbinds))
	return res
}

// summarizeVarbinds renders at most eight varbinds plus the total count.
func summarizeVarbinds(vbs []Varbind) string {
	const maxShown = 8
	if len(vbs) <= maxShown {
		return fmt.Sprintf("%v", vbs)
	}
	return fmt.Sprintf("%v ... (%d total)", vbs[:maxShown], len(vbs))
}

// skipUnsupported converts a documented vendor limitation into a skip. The
// reason is printed, so "not covered because pysnmp cannot do this" never
// looks like "covered and passing".
func skipUnsupported(t *testing.T, res Result) {
	t.Helper()
	if res.ErrorKind == KindUnsupported {
		t.Skipf("vendor does not support this operation: %s", res.Error)
	}
}
