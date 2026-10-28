// fuzz_test.go: fuzz target for the persisted engine store. This file is
// the anti-rollback memory of the authoritative engine — it lives on disk,
// survives crashes and is copied between HA replicas, so a corrupt or
// truncated file must be a hard error (never a silently empty state, which
// would reset engineBoots and re-open the replay window).
//
//	go test ./internal/cache -run '^$' -fuzz FuzzLoadEngine -fuzztime 30s
package cache

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoadEngine(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"engine_id":"gA==","boots":3,"last_boots":3}`),
		[]byte(`{"engine_id":"","boots":4294967295,"last_boots":4294967295}`),
		[]byte(`{"engine_id":null}`),
		[]byte(`not json`),
		[]byte(`{}`),
		[]byte(`{"boots":-1}`),
		[]byte(``),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	dir := f.TempDir()
	path := filepath.Join(dir, "engine.json")

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		prev, err := store.LoadEngine()
		if err != nil {
			// Corrupt input is a hard error; the store must not have
			// repaired or truncated itself behind our back.
			if got, rerr := os.ReadFile(path); rerr != nil {
				t.Fatalf("store file disappeared after a corrupt load: %v", rerr)
			} else if string(got) != string(data) {
				t.Fatalf("corrupt store was rewritten by LoadEngine")
			}
			return
		}
		if prev == nil {
			return
		}

		// Whatever loaded must be startable: boots may not go backwards,
		// and the engine ID is either the persisted one or a fresh one.
		clock, cerr := NewEngineClock(store, nil, nil)
		if cerr != nil {
			t.Fatalf("loadable engine state could not be started: %v", cerr)
		}
		if len(prev.EngineID) > 0 {
			if string(clock.EngineID()) != string(prev.EngineID) {
				t.Fatalf("engine ID changed across restart: %x -> %x", prev.EngineID, clock.EngineID())
			}
			if prev.Boots != ^uint32(0) && clock.Boots() != prev.Boots+1 {
				t.Fatalf("boots %d -> %d, want an increment", prev.Boots, clock.Boots())
			}
		}
		// Anti-rollback: the new state is persisted and never regresses.
		reloaded, rerr := store.LoadEngine()
		if rerr != nil {
			t.Fatalf("reload after start: %v", rerr)
		}
		if reloaded == nil {
			t.Fatal("State vanished after start")
		}
		if reloaded.Boots < clock.Boots() {
			t.Fatalf("persisted boots %d < running boots %d", reloaded.Boots, clock.Boots())
		}
	})
}
