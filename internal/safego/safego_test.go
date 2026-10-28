package safego

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestDispatchContainsPanic: a panicking handler must not escape, and the
// recovery must be loud (error level, the panic value, a stack).
func TestDispatchContainsPanic(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	log := zap.New(core)

	ran := false
	Dispatch(log, "test handler", func() {
		ran = true
		panic("boom")
	})
	if !ran {
		t.Fatal("handler did not run")
	}

	entries := logs.FilterMessage("recovered panic in test handler").All()
	if len(entries) != 1 {
		t.Fatalf("got %d recovery log entries, want 1 (all: %v)", len(entries), logs.All())
	}
	e := entries[0]
	if e.Level != zapcore.ErrorLevel {
		t.Fatalf("recovery logged at %v, want error: a recovered panic is a bug", e.Level)
	}
	ctx := e.ContextMap()
	if got := ctx["panic"]; got != "boom" {
		t.Fatalf("logged panic value = %v, want %q", got, "boom")
	}
	// zap encodes a ByteString field as []byte; some encoders hand the
	// observer a string. Accept either, insist on the content.
	stackLen := 0
	switch v := ctx["stack"].(type) {
	case []byte:
		stackLen = len(v)
	case string:
		stackLen = len(v)
	}
	if stackLen == 0 {
		t.Fatalf("no stack logged (context %v): a recovered panic must stay diagnosable", ctx)
	}
}

// TestDispatchPassesThrough: the normal path is unchanged — a handler that
// returns normally produces no log at all (so the wrapper cannot be mistaken
// for error handling).
func TestDispatchPassesThrough(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	Dispatch(zap.New(core), "quiet handler", func() {})
	if n := logs.Len(); n != 0 {
		t.Fatalf("Dispatch logged %d entries on the happy path, want 0", n)
	}
}

// TestDispatchNilLogger: the helper is used in tests and in early startup
// where no logger exists yet. A panic must still be contained.
func TestDispatchNilLogger(t *testing.T) {
	done := make(chan struct{})
	func() {
		defer close(done)
		Dispatch(nil, "no logger", func() { panic("still contained") })
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Dispatch blocked with a nil logger")
	}
}

// TestGoContainsPanic: a per-session goroutine that panics must not kill the
// process, and Go must still return immediately (it is a goroutine starter,
// not a runner).
func TestGoContainsPanic(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	done := make(chan struct{})
	start := time.Now()
	Go(zap.New(core), "session", func() {
		defer close(done)
		panic("session exploded")
	})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Go blocked for %s; it must return immediately", elapsed)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the goroutine never ran")
	}
	// The recovery log is written by the goroutine; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if logs.FilterMessage("recovered panic in session").Len() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no recovery log from the goroutine: %v", logs.All())
}

// TestRecoveryIsPerCall: one panicking dispatch must not poison the next
// one — the read loop continues with the same wrapper.
func TestRecoveryIsPerCall(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	log := zap.New(core)

	var mu sync.Mutex
	var ok int
	for i := 0; i < 3; i++ {
		Dispatch(log, "loop body", func() {
			mu.Lock()
			ok++
			mu.Unlock()
			if ok == 2 {
				panic("only the second one")
			}
		})
	}
	if ok != 3 {
		t.Fatalf("ran %d of 3 iterations: one panic stopped the loop", ok)
	}
	if n := logs.FilterMessage("recovered panic in loop body").Len(); n != 1 {
		t.Fatalf("got %d recoveries, want exactly 1", n)
	}
}
