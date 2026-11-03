package tsm

import "testing"

// TestSessionLimiter pins the shared front-session budget used by the
// multi-agent gateway: Acquire is non-blocking, Release returns a slot,
// and a nil limiter is the unlimited fallback.
func TestSessionLimiter(t *testing.T) {
	l := NewSessionLimiter(2)
	if got := l.Max(); got != 2 {
		t.Fatalf("Max = %d, want 2", got)
	}
	if !l.Acquire() {
		t.Fatal("first acquire below the cap failed")
	}
	if !l.Acquire() {
		t.Fatal("second acquire below the cap failed")
	}
	if l.Acquire() {
		t.Fatal("acquire above the cap succeeded")
	}
	l.Release()
	if !l.Acquire() {
		t.Fatal("released slot was not reusable")
	}
	l.Release()
	l.Release()

	if got := NewSessionLimiter(0).Max(); got != defaultMaxSessions {
		t.Fatalf("zero max = %d, want %d", got, defaultMaxSessions)
	}

	var nilL *SessionLimiter
	if !nilL.Acquire() {
		t.Fatal("nil limiter is not unlimited")
	}
	nilL.Release()
	if got := nilL.Max(); got != 0 {
		t.Fatalf("nil Max = %d, want 0", got)
	}
}
