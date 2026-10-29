// Soak test for the per-client rate limiter, in package access so it can see
// the bucket table directly.
//
// The unit tests already pin the two correctness properties (the table is
// swept after an idle period, and a full table refuses a new client). What
// they cannot show is that those properties hold under a sustained flood of
// spoofed sources: the sweep runs on a real clock, so a long run interleaves
// allocations, sweeps and refusals in an order no unit test reproduces. That
// is the DoS premise — an attacker chooses the source addresses — so it gets
// a soak rather than a plausible-looking unit test.
package access

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// TestSoakRateLimiterSpoofedSources floods the limiter with distinct source
// addresses for the soak budget and asserts the table stays bounded, every
// request from a source it has never seen is refused once the table is full,
// and neither goroutines nor the live heap grow.
func TestSoakRateLimiterSpoofedSources(t *testing.T) {
	budget := testkit.SoakDuration(t)

	lim := NewLimit(100) // one token per request is irrelevant: each source is new
	baseline := snap(t)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	deadline := time.Now().Add(budget)
	var allowed, refused atomic.Int64
	var maxTable int

	// One producer is the harshest honest shape: the limiter's mutex is the
	// shared resource, so parallel producers would only measure contention.
	for n := 0; time.Now().Before(deadline); n++ {
		// 10.0.0.0/8 gives 16.7M distinct spoofed sources — far past the
		// 4096-entry cap, so the flood necessarily crosses it.
		ip := net.IPv4(10, byte(n>>16), byte(n>>8), byte(n))
		if lim.Allow(ip) {
			allowed.Add(1)
		} else {
			refused.Add(1)
		}
		if n%4096 == 0 {
			size := lim.Len()
			if size > maxTable {
				maxTable = size
			}
			if size > limitMaxBuckets {
				t.Fatalf("bucket table grew to %d entries, cap is %d", size, limitMaxBuckets)
			}
			// Keep the flood hot without pinning a core for ten minutes.
			time.Sleep(100 * time.Microsecond)
		}
	}

	if maxTable != limitMaxBuckets {
		t.Fatalf("table peaked at %d entries, want the cap %d — the flood never reached it", maxTable, limitMaxBuckets)
	}
	if refused.Load() == 0 {
		t.Fatal("no request was refused: the fail-closed cap did not engage under the flood")
	}

	// The property that matters operationally: after minutes of churn, a
	// source the proxy has never seen is still refused, not admitted.
	if lim.Allow(net.IPv4(192, 0, 2, 77)) {
		t.Fatal("a never-seen source was admitted while the table was full (fail-open)")
	}

	after := snap(t)
	if after.goroutines > baseline.goroutines+2 {
		t.Fatalf("goroutines %d -> %d during the soak", baseline.goroutines, after.goroutines)
	}

	runtime.GC()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	// The table is bounded, so live heap must not track the request count.
	if grew := int64(end.HeapAlloc) - int64(base.HeapAlloc); grew > 16<<20 {
		t.Fatalf("live heap grew %s during the soak (base %s, end %s): the table is not the only thing being retained",
			time.Duration(grew), fmtBytes(base.HeapAlloc), fmtBytes(end.HeapAlloc))
	}

	t.Logf("soak: %s, %d admitted, %d refused, table %d/%d, goroutines %d",
		budget, allowed.Load(), refused.Load(), lim.Len(), limitMaxBuckets, after.goroutines)
}

type snapshot struct{ goroutines int }

func snap(t *testing.T) snapshot {
	t.Helper()
	return snapshot{goroutines: runtime.NumGoroutine()}
}

func fmtBytes(b uint64) string {
	const unit = 1 << 20
	return fmt.Sprintf("%.1fMiB", float64(b)/unit)
}
