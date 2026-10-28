// fuzz_test.go: fuzz targets for the notification filter. The trap OID is
// attacker-influenced on every clear notification ingress, so Allowed must
// be total: any string in, a bool out, no panic.
//
//	go test ./internal/notifyfilter -run '^$' -fuzz FuzzAllowed -fuzztime 30s
package notifyfilter

import (
	"strings"
	"testing"
)

func FuzzAllowed(f *testing.F) {
	seeds := []string{
		"",
		"1.3.6.1.4.1.99.1",
		"1.3.6.1.4.1.99",
		".1.3.6.1.4.1.99.1",
		"1.3.6.1.4.1.9999",
		"1.3.6.1.4.1.99.1.0.1",
		"1..3.6",
		"-1",
		"1.3.6.1.999999999999999999999",
		"18446744073709551616",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	allow, err := New("allow", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		f.Fatal(err)
	}
	deny, err := New("deny", []string{"1.3.6.1.4.1.99"})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, oid string) {
		// Never panic, and be deterministic.
		a := allow.Allowed(oid)
		if a != allow.Allowed(oid) {
			t.Fatalf("Allowed is not deterministic for %q", oid)
		}
		d := deny.Allowed(oid)
		if a == d {
			t.Fatalf("allow and deny agreed for %q: allow=%v deny=%v", oid, a, d)
		}
		// Prefix monotonicity: extending an OID keeps a matching prefix
		// matched, so an allow-filter that accepts a parent must accept its
		// child, and a deny-filter that rejects a parent must reject the
		// child as well.
		child := oid + ".1"
		if a && !allow.Allowed(child) {
			t.Fatalf("allow filter accepted %q but rejected its child %q", oid, child)
		}
		if !d && deny.Allowed(child) {
			t.Fatalf("deny filter rejected %q but accepted its child %q", oid, child)
		}
		// A nil filter is the "no policy" case and allows everything.
		var nilFilter *Filter
		if !nilFilter.Allowed(oid) {
			t.Fatalf("nil filter rejected %q", oid)
		}
	})
}

func FuzzNew(f *testing.F) {
	f.Add("allow", "1.3.6.1.4.1.99")
	f.Add("deny", ".1.3")
	f.Add("", "0.0")
	f.Add("bogus", "1.3")
	f.Add("allow", "1.3.x")

	f.Fuzz(func(t *testing.T, action, oid string) {
		filt, err := New(action, []string{oid})
		if err != nil {
			return
		}
		// A filter that compiles must be usable for every input.
		_ = filt.Allowed("1.3.6.1.4.1.99.1")
		_ = filt.Allowed(strings.Repeat("1.", 1000))
	})
}
