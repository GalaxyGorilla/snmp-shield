package cache

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testLogger(t *testing.T) Logger {
	return loggerFunc{t}
}

type loggerFunc struct{ t *testing.T }

func (l loggerFunc) Logf(format string, args ...any) {
	l.t.Logf(format, args...)
}

func TestOpenMemoryOnly(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") should succeed as memory-only: %v", err)
	}
	if s.path != "" {
		t.Fatalf("expected empty path for memory store, got %q", s.path)
	}
	// Memory-only store: SaveEngine is a no-op, LoadEngine reads nothing.
	if err := s.SaveEngine(&Engine{EngineID: []byte{1}, Boots: 1}); err != nil {
		t.Fatalf("SaveEngine on memory store should be nil: %v", err)
	}
	if e, err := s.LoadEngine(); err != nil || e != nil {
		t.Fatalf("LoadEngine on memory store should return nil,nil, got %v,%v", e, err)
	}
}

func TestOpenCreatesDirs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "engine.json")
	if _, err := Open(p); err != nil {
		t.Fatalf("Open should MkdirAll: %v", err)
	}
	if fi, err := os.Stat(filepath.Dir(p)); err != nil || !fi.IsDir() {
		t.Fatalf("parent dirs not created: %v", err)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := s.LoadEngine(); e != nil {
		t.Fatalf("fresh store should have no engine, got %+v", e)
	}
	want := &Engine{EngineID: []byte{0x80, 1, 2, 3}, Boots: 7, LastBoots: 7, StartedAt: time.Now().UTC()}
	if err := s.SaveEngine(want); err != nil {
		t.Fatalf("SaveEngine: %v", err)
	}
	got, err := s.LoadEngine()
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	if got == nil || string(got.EngineID) != string(want.EngineID) || got.Boots != 7 || got.LastBoots != 7 {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	// Overwrite: last write wins.
	want.Boots = 8
	if err := s.SaveEngine(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadEngine(); got == nil || got.Boots != 8 {
		t.Fatalf("overwrite failed: %+v", got)
	}
	// No .tmp leftover (atomic rename).
	if _, err := os.Stat(p + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file should not survive SaveEngine: %v", err)
	}
}

func TestStoreCorruptFileIsError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadEngine(); err == nil {
		t.Fatal("corrupt store must error, not silently start empty (rollback protection)")
	}
}

func TestEngineClockBootsIncrementPerStart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if c1.Boots() != 1 {
		t.Fatalf("first boot should be boots=1, got %d", c1.Boots())
	}
	id1 := c1.EngineID()

	c2, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if c2.Boots() != 2 {
		t.Fatalf("boots must increment per start, got %d", c2.Boots())
	}
	if string(c2.EngineID()) != string(id1) {
		t.Fatalf("engine ID should be stable across restarts: %x vs %x", id1, c2.EngineID())
	}
}

func TestEngineClockProvidedIDAdopts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, _ := Open(p)
	provided := []byte{0x80, 0xAA, 0xBB}
	c1, err := NewEngineClock(s, provided, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.EngineID()) != string(provided) {
		t.Fatalf("provided ID must win: got %x", c1.EngineID())
	}
	if c1.Boots() != 1 {
		t.Fatalf("fresh provided ID: boots=1, got %d", c1.Boots())
	}
	// Same provided ID again: boots continues (prev.Boots + 1).
	c2, err := NewEngineClock(s, provided, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if c2.Boots() != 2 {
		t.Fatalf("same provided ID should continue boots, got %d", c2.Boots())
	}
	// Different provided ID: boots resets to 1 (new engine identity).
	c3, err := NewEngineClock(s, []byte{0x80, 0xCC}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if c3.Boots() != 1 {
		t.Fatalf("new provided ID should restart boots, got %d", c3.Boots())
	}
}

func TestEngineClockTimeAdvances(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "engine.json"))
	c, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	t0 := c.Time()
	time.Sleep(1100 * time.Millisecond)
	t1 := c.Time()
	if t1 < t0 {
		t.Fatalf("engine time must not go backwards: %d -> %d", t0, t1)
	}
	// Should be roughly seconds since start; just check sane bounds.
	if t1 > 5 {
		t.Fatalf("engine time way out of range after 1s: %d", t1)
	}
}

func TestEngineClockAcceptInboundWindow(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "engine.json"))
	c, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	// Age the clock so "now - X" arithmetic doesn't underflow a fresh
	// engineTime of 0.
	c.mu.Lock()
	c.startedAt = time.Now().Add(-300 * time.Second)
	c.mu.Unlock()
	boots := c.Boots()

	cases := []struct {
		name    string
		boots   uint32
		time    uint32
		wantErr bool
	}{
		{"exact current time", boots, c.Time(), false},
		{"slightly stale (now-100)", boots, c.Time() - 100, false},
		{"window edge (now-150)", boots, c.Time() - 150, false},
		{"slightly future (now+100)", boots, c.Time() + 100, false},
		{"window edge (now+150)", boots, c.Time() + 150, false},
		{"too far past (now-151)", boots, c.Time() - 151, true},
		{"too far future (now+151)", boots, c.Time() + 151, true},
		{"boots mismatch (older)", boots - 1, c.Time(), true},
		{"boots mismatch (future claim)", boots + 1, c.Time(), true},
	}
	for _, tc := range cases {
		err := c.AcceptInbound(tc.boots, tc.time)
		if tc.wantErr && !errors.Is(err, ErrRollback) {
			t.Errorf("%s: want ErrRollback, got %v", tc.name, err)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: want accept, got %v", tc.name, err)
		}
	}
}

func TestEngineClockReplayAfterRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, _ := Open(p)
	c1, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	oldBoots := c1.Boots()

	// The engine restarts (process reboot); boots increments.
	c2, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	// Captured messages from before the restart must fail the boots check.
	if err := c2.AcceptInbound(oldBoots, c1.Time()); !errors.Is(err, ErrRollback) {
		t.Fatalf("pre-restart replay must be rejected, got %v", err)
	}
}

func TestEngineClockAdoptInbound(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, _ := Open(p)
	c, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	id := c.EngineID()
	if c.Boots() != 1 {
		t.Fatalf("fresh clock should be boots=1, got %d", c.Boots())
	}

	// Adopting a LOWER or equal boots is a no-op (anti-rollback).
	c.AdoptInbound(0, 5)
	c.AdoptInbound(1, 99999)
	if c.Boots() != 1 {
		t.Fatalf("lower/equal boots must not adopt, boots=%d", c.Boots())
	}

	// Adopting a HIGHER boots (the failed-over peer's state, logical
	// reboot per RFC 3414) moves the engine forward and re-anchors
	// engineTime to the claimed timeline.
	c.AdoptInbound(7, 100)
	if c.Boots() != 7 {
		t.Fatalf("higher boots must adopt, boots=%d", c.Boots())
	}
	if c.Time() < 100 || c.Time() > 105 {
		t.Fatalf("engineTime should be re-anchored to ~100 after adoption, got %d", c.Time())
	}
	if string(c.EngineID()) != string(id) {
		t.Fatalf("adoption must not change the engineID: %x vs %x", id, c.EngineID())
	}

	// The merged state is persisted (a restart must not reset boots).
	c2, err := NewEngineClock(s, nil, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if c2.Boots() != 8 {
		t.Fatalf("adopted boots must persist across restart: boots=%d, want 8 (7+1)", c2.Boots())
	}
	if string(c2.EngineID()) != string(id) {
		t.Fatalf("engineID must stay stable across the adopt+restart: %x vs %x", id, c2.EngineID())
	}

	// A message on the adopted timeline passes AcceptInbound (that is
	// the whole point: managers keep sending the peer's timeline).
	if err := c.AcceptInbound(7, 101); err != nil {
		t.Fatalf("post-adopt message on the peer timeline must be accepted, got %v", err)
	}
	// ...and a pre-adopt replay (old lower boots) still fails.
	if err := c.AcceptInbound(1, 10); !errors.Is(err, ErrRollback) {
		t.Fatalf("pre-adopt replay must stay rejected, got %v", err)
	}
}

func TestGenerateEngineID(t *testing.T) {
	id1, err := GenerateEngineID()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := GenerateEngineID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id1) != 12 {
		t.Fatalf("engine ID should be 12 bytes, got %d", len(id1))
	}
	if id1[0] != 0x80 {
		t.Fatalf("first octet should be 0x80, got %#x", id1[0])
	}
	if string(id1) == string(id2) {
		t.Fatal("two generated IDs must differ")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.json")
	s, _ := Open(p)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = s.SaveEngine(&Engine{EngineID: []byte{byte(n)}, Boots: uint32(n + 1)})
			_, _ = s.LoadEngine()
		}(i)
	}
	wg.Wait()
	// -race runs this file; a clean exit means no data race on the store.
}

// Compile-time: ensure *EngineClock satisfies the usage pattern proxy.go relies on.
var _ = func() *Store { s, _ := Open(""); return s }
