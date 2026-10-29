package testkit

import (
	"os"
	"testing"
	"time"
)

// SoakDuration returns the wall-clock budget for a soak test.
//
// Soak tests are skipped unless SNMP_SHIELD_SOAK=1, because their whole point
// is to run for minutes: `go test ./...` must stay a fast edit-loop command,
// while `make soak` opts in explicitly. SNMP_SHIELD_SOAK_DURATION overrides
// the 10-minute default (any positive Go duration, e.g. "90s").
//
// A soak that skips silently is worthless, so the skip reason names the
// switch that turns it on.
func SoakDuration(t testing.TB) time.Duration {
	t.Helper()
	if os.Getenv("SNMP_SHIELD_SOAK") != "1" {
		t.Skip("soak test: set SNMP_SHIELD_SOAK=1 (`make soak`) to run it")
	}
	const def = 10 * time.Minute
	v := os.Getenv("SNMP_SHIELD_SOAK_DURATION")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		t.Fatalf("SNMP_SHIELD_SOAK_DURATION=%q: want a positive Go duration such as 90s or 10m", v)
	}
	return d
}
