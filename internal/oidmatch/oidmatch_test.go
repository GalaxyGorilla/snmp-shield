package oidmatch

import "testing"

func TestCanonical(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1.0"},
		{".1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1.0"},
		{"1.03.6.1", "1.3.6.1"},
		{" 1.3.6.1 ", "1.3.6.1"},
	}
	for _, tc := range cases {
		got, err := Canonical(tc.in)
		if err != nil {
			t.Errorf("Canonical(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "not-an-oid", "1", "1.x.3"} {
		if _, err := Canonical(bad); err == nil {
			t.Errorf("Canonical(%q): expected error", bad)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		prefix, oid string
		want        bool
	}{
		// arc-boundary rule: a shorter numeric prefix must not match
		{"1.3.6.1.4.1.99", "1.3.6.1.4.1.9999", false},
		{"1.3.6.1.4.1.99", "1.3.6.1.4.1.99", true},
		{"1.3.6.1.4.1.99", "1.3.6.1.4.1.99.5.1", true},
		{"1.3.6.1.4.1", "1.3.6.1.4.1.9999.5", true},
		{"1.3.6.1.4.1.99.5", "1.3.6.1.4.1.99", false},
		{"1.3.6.1", "1.3.6.10", false},
		{"", "1.3.6.1", true},
	}
	for _, tc := range cases {
		if got := Match(tc.prefix, tc.oid); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.prefix, tc.oid, got, tc.want)
		}
	}
}
