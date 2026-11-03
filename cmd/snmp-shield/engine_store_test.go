// Process-level fail-closed tests for the persisted USM engine store.
//
// The store is the anti-rollback anchor: engineBoots must never decrease
// across a restart. A corrupt or torn file therefore has to stop the daemon,
// not be treated as "no previous state" — silently starting at boots=1 is
// exactly the replay window the store exists to close.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/cache"
)

// runArgsTimed runs the real CLI entry point with args, with a deadline so a
// regression that starts serving instead of failing closed cannot hang the
// suite. Output goes to /dev/null; the exit code is the assertion.
func runArgsTimed(t *testing.T, args []string, timeout time.Duration) int {
	t.Helper()
	oldArgs := os.Args
	oldOut, oldErr := os.Stdout, os.Stderr
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Args = args
	os.Stdout = devnull
	os.Stderr = devnull
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldOut
		os.Stderr = oldErr
		_ = devnull.Close()
	}()

	done := make(chan int, 1)
	go func() { done <- run() }()
	select {
	case rc := <-done:
		return rc
	case <-time.After(timeout):
		t.Fatalf("daemon did not fail closed on a corrupt engine store (still running after %s)", timeout)
		return -1
	}
}

func TestRunFailsClosedOnCorruptEngineStore(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"invalid json", "{not json"},
		{"truncated", `{"engine_id":"gAEC","boots":`},
		{"empty object", `{}`},
		{"json null", `null`},
		{"zero boots", `{"engine_id":"gAEC","boots":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "engine.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}

			rc := runArgsTimed(t, []string{"snmp-shield", "gateway",
				"--security", "usm-gateway",
				"--listen", "127.0.0.1:0",
				"--agent", "127.0.0.1:16161",
				"--auth-pass", "authpass",
				"--priv-pass", "privpass",
				"--engine-store", path,
			}, 10*time.Second)
			if rc != 1 {
				t.Fatalf("corrupt engine store exited %d, want 1", rc)
			}

			// The operator needs the original bytes to diagnose the crash;
			// a failed start must not "repair" the file.
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("engine store disappeared after a failed start: %v", err)
			}
			if string(got) != tc.data {
				t.Fatalf("failed start rewrote the engine store: %q -> %q", tc.data, got)
			}
		})
	}
}

// TestRunStartsFromCommittedStoreAfterTornWrite is the power-loss companion:
// a crash between the temp write and the rename leaves a partial .tmp beside
// an intact store. The daemon must start from the committed state and
// increment boots, not adopt the torn temp file.
func TestRunStartsFromCommittedStoreAfterTornWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json")
	// engineID = 0x80 0x01 0x02 0x03, committed boots = 4.
	committed := `{"engine_id":"gAECAw==","boots":4,"last_boots":4,"started_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(committed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", []byte(`{"engine_id":"gA`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Preflight runs the same loader the daemon uses; a torn temp file must
	// not make the committed store look unusable.
	if ch := checkEngineStore(path); !ch.OK {
		t.Fatalf("committed store with a torn temp file failed preflight: %s", ch.Detail)
	}

	s, err := cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.LoadEngine()
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	if e == nil || e.Boots != 4 || len(e.EngineID) != 4 || e.EngineID[0] != 0x80 {
		t.Fatalf("loaded engine = %+v, want the committed boots=4 state", e)
	}
}
