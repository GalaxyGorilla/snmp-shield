// fuzz_test.go: fuzz target for the write policy's PDU decoder. A SET
// arrives before any authorization decision, so Allowed must be total and
// must fail closed: garbage is a refusal, never a panic and never an
// accidental allow.
//
//	go test ./internal/access -run '^$' -fuzz FuzzAllowed -fuzztime 30s
package access

import (
	"testing"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

func FuzzAllowed(f *testing.F) {
	allowDeny, err := NewWritePolicy(false, []WriteRule{
		{OID: "1.3.6.1.4.1.99", Allow: true},
		{OID: "1.3.6.1.4.1.99.9", Allow: false},
	})
	if err != nil {
		f.Fatal(err)
	}
	denyAll, err := NewWritePolicy(false, []WriteRule{{OID: "1.3", Allow: true}})
	if err != nil {
		f.Fatal(err)
	}
	allowAll, err := NewWritePolicy(true, nil)
	if err != nil {
		f.Fatal(err)
	}
	ro := NewReadOnly()

	vb := func(oid string) []byte {
		return msg.BuildVarbinds([]msg.Varbind{{OID: oid, Type: 0x02, Value: []byte{1}}})
	}
	f.Add(vb("1.3.6.1.4.1.99.1.0"))
	f.Add(vb("1.3.6.1.4.1.99.9.1.0"))
	f.Add(vb("1.3.6.1.2.1.1.5.0"))
	f.Add([]byte{})
	f.Add([]byte{0x30})

	f.Fuzz(func(t *testing.T, varbindList []byte) {
		pdu := msg.BuildPDU(msg.PDUSetRequest, 1, 0, 0, varbindList)

		// The coarse switch refuses every SET whatever it contains.
		if ro.Allowed(pdu) {
			t.Fatalf("read-only policy allowed %x", pdu)
		}

		// Undecodable or empty SETs are denied, and the decision is stable.
		decoded, derr := msg.ParseVarbinds(varbindList)
		got := allowDeny.Allowed(pdu)
		if got != allowDeny.Allowed(pdu) {
			t.Fatalf("Allowed is not deterministic for %x", pdu)
		}
		unreadable := derr != nil || len(decoded) == 0
		if unreadable && got {
			t.Fatalf("undecodable/empty SET was allowed: %x (err %v)", pdu, derr)
		}
		// A blanket deny-default policy never allows anything it cannot see.
		if unreadable && denyAll.Allowed(pdu) {
			t.Fatalf("deny-by-default policy allowed an unreadable SET: %x", pdu)
		}
		// Even an explicit allow-everything policy refuses an unreadable
		// SET: the fail-closed cap beats the default. A decodable SET is
		// exactly what that policy exists to permit.
		if unreadable {
			if allowAll.Allowed(pdu) {
				t.Fatalf("allow-everything policy allowed an unreadable SET: %x", pdu)
			}
		} else if !allowAll.Allowed(pdu) {
			t.Fatalf("allow-everything policy refused a decodable SET: %x", pdu)
		}

		// Non-SET PDUs are never the write policy's business.
		for _, typ := range []byte{msg.PDUGetRequest, msg.PDUGetNextRequest, msg.PDUGetBulkRequest, msg.PDUGetResponse} {
			read := msg.BuildPDU(typ, 1, 0, 0, varbindList)
			if !ro.Allowed(read) {
				t.Fatalf("read-only policy refused a non-SET PDU (type 0x%02x)", typ)
			}
		}
	})
}
