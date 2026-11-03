package testkit

import "testing"

// TestFreeUDPPortIsUnique pins the process-wide uniqueness contract: two
// fixtures in one test must never be handed the same port, including when
// the kernel would happily reuse the port just freed by the previous probe.
func TestFreeUDPPortIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		addr := FreeUDPPort(t, "")
		if seen[addr] {
			t.Fatalf("FreeUDPPort returned %s twice", addr)
		}
		seen[addr] = true
	}
}
