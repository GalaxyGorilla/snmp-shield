package notifyfilter

import (
	"testing"
)

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		oids    []string
		wantErr bool
	}{
		{"empty action defaults to allow", "", []string{"1.3.6.1"}, false},
		{"allow", "allow", []string{"1.3.6.1"}, false},
		{"deny", "deny", []string{"1.3.6.1"}, false},
		{"unknown action", "drop", []string{"1.3.6.1"}, true},
		{"no oids", "allow", nil, true},
		{"empty oids", "allow", []string{}, true},
		{"bad oid", "allow", []string{"not-an-oid"}, true},
		{"one arc", "allow", []string{"1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := New(tc.action, tc.oids)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%q, %v): expected error, got nil", tc.action, tc.oids)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q, %v): %v", tc.action, tc.oids, err)
			}
			if f == nil {
				t.Fatal("New returned nil filter")
			}
		})
	}
}

func TestAllowFilter(t *testing.T) {
	f, err := New("allow", []string{"1.3.6.1.4.1.8072"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		oid  string
		want bool
	}{
		{"1.3.6.1.4.1.8072", true},       // exact
		{"1.3.6.1.4.1.8072.999", true},   // child prefix
		{"1.3.6.1.4.1.8072.3.1.1", true}, // deep child
		{"1.3.6.1.4.1.80721", false},     // boundary: no partial arc match
		{"1.3.6.1.4.1", false},           // parent: not covered
		{"1.3.6.1.6.3.1.1.5.1", false},   // unrelated
		{"", false},                      // empty OID matches nothing
	}
	for _, tc := range cases {
		if got := f.Allowed(tc.oid); got != tc.want {
			t.Errorf("Allowed(%q) = %v, want %v", tc.oid, got, tc.want)
		}
	}
}

func TestDenyFilter(t *testing.T) {
	f, err := New("deny", []string{"1.3.6.1.6.3.1.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		oid  string
		want bool
	}{
		{"1.3.6.1.6.3.1.1.5.1", false},  // child: denied
		{"1.3.6.1.6.3.1.1.5", false},    // exact: denied
		{"1.3.6.1.6.3.1.1.4.1.0", true}, // unrelated: allowed
		{"1.3.6.1.6.3.1.1.51", true},    // boundary: partial arc not denied
	}
	for _, tc := range cases {
		if got := f.Allowed(tc.oid); got != tc.want {
			t.Errorf("Allowed(%q) = %v, want %v", tc.oid, got, tc.want)
		}
	}
}

func TestCanonicalization(t *testing.T) {
	f, err := New("", []string{"1.03.6.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Allowed("1.3.6.1") {
		t.Error(`"1.03.6.1" should canonicalize to "1.3.6.1"`)
	}
	if !f.Allowed("1.3.6.1.2") {
		t.Error("child of canonicalized prefix should match")
	}
}

func TestMultiOIDFilter(t *testing.T) {
	f, err := New("allow", []string{"1.3.6.1.4.1.8072", "1.3.6.1.6.3.1.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Allowed("1.3.6.1.4.1.8072.2") || !f.Allowed("1.3.6.1.6.3.1.1.5.1") {
		t.Error("both prefixes should match")
	}
	if f.Allowed("1.3.6.1.2.1.1.5.0") {
		t.Error("unrelated OID should not match")
	}
}

func TestNilFilterAllowsAll(t *testing.T) {
	var f *Filter
	if !f.Allowed("1.2.3.4.5") {
		t.Error("nil filter must allow everything")
	}
}

func TestFrom(t *testing.T) {
	if From() != nil {
		t.Error("From() with no args must return nil")
	}
	if From(nil, nil) != nil {
		t.Error("From(nil, nil) must return nil")
	}
	a, err := New("allow", []string{"1.3.6.1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("deny", []string{"1.3.6.1.6"})
	if err != nil {
		t.Fatal(err)
	}
	if From(nil, a, b) != a {
		t.Error("From must return the first non-nil filter")
	}
	if From(a, b) != a {
		t.Error("From must return the first filter")
	}
}
