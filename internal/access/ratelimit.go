package access

import (
	"net"
	"sync"
	"time"
)

// Limits on the per-client bucket table. A UDP front leg sees whatever
// source addresses arrive, so the table must never grow without bound: it
// is swept periodically, and once it is full a new client is refused
// rather than allowed to allocate (the rate limit is the DoS guard, so
// failing closed there is the right call).
const (
	limitMaxBuckets = 4096
	limitIdleAfter  = 5 * time.Minute
	limitSweepEvery = time.Minute
)

// bucket is one client's token bucket.
type bucket struct {
	tokens float64
	max    float64
	refill float64 // tokens per second
	last   time.Time
	seen   time.Time
}

// Limit is a per-client token bucket capping front-leg request rate. The
// bucket starts full and refills continuously; capacity is one second's
// worth of tokens (min 1), so short bursts up to the configured rate are
// absorbed instead of rejected.
//
// A nil *Limit is unlimited: every rate check is nil-guarded.
type Limit struct {
	mu       sync.Mutex
	perSec   float64
	buckets  map[string]*bucket
	lastGC   time.Time
	nowFn    func() time.Time // stubbed in tests
	rejected float64          // observability: requests refused by the cap
}

// NewLimit builds a per-client limiter. perSec <= 0 returns nil
// (unlimited).
func NewLimit(perSec int) *Limit {
	if perSec <= 0 {
		return nil
	}
	max := float64(perSec)
	return &Limit{
		perSec:  max,
		buckets: make(map[string]*bucket),
		nowFn:   time.Now,
		// lastGC is initialized lazily on the first Allow so the limiter
		// never depends on construction-time clock reads (keeps test
		// clock injection exact).
	}
}

// Allow reports whether one request from ip is admitted under the
// configured rate and, if so, consumes one token. A nil limit allows
// everything.
func (l *Limit) Allow(ip net.IP) bool {
	if l == nil {
		return true
	}
	key := ip.String()

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFn()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= limitMaxBuckets {
			// Fail closed: an unbounded table would be the DoS.
			l.rejected++
			return false
		}
		b = &bucket{tokens: l.perSec, max: l.perSec, refill: l.perSec, last: now}
		l.buckets[key] = b
	}
	b.seen = now

	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = min(b.max, b.tokens+elapsed*b.refill)

	if b.tokens < 1 {
		l.rejected++
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been idle for a while. Must be called
// with l.mu held.
func (l *Limit) sweep(now time.Time) {
	if l.lastGC.IsZero() {
		l.lastGC = now
		return
	}
	if now.Sub(l.lastGC) < limitSweepEvery {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > limitIdleAfter {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of tracked clients (tests/observability).
func (l *Limit) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
