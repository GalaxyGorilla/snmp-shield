package access

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

func TestNewList(t *testing.T) {
	l, err := NewList([]string{"10.0.0.5", "10.8.0.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"10.8.0.99", true},
		{"10.9.0.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}
	for _, tc := range cases {
		if got := l.Allowed(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("Allowed(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if l.Len() != 3 {
		t.Errorf("Len() = %d, want 3", l.Len())
	}

	// empty list = no restriction (nil), and nil allows everything
	n, err := NewList(nil)
	if err != nil || n != nil {
		t.Errorf("NewList(nil) = %v, %v; want nil, nil", n, err)
	}
	if !n.Allowed(net.ParseIP("203.0.113.9")) {
		t.Error("nil list rejected a client")
	}

	if _, err := NewList([]string{"not-an-ip"}); err == nil {
		t.Error("invalid allow entry accepted")
	}
}

// setPDU builds a real SET request PDU touching the given OIDs.
func setPDU(t *testing.T, oids ...string) []byte {
	t.Helper()
	var vbs []byte
	for _, o := range oids {
		ber, err := msg.EncodeOID(o)
		if err != nil {
			t.Fatalf("encode %s: %v", o, err)
		}
		// varbind = SEQUENCE { OID, INTEGER value }
		inner := msg.AppendTLV(nil, 0x06, ber)
		inner = msg.AppendTLV(inner, 0x02, []byte{0x01})
		vbs = msg.AppendTLV(vbs, 0x30, inner)
	}
	return msg.BuildPDU(msg.PDUSetRequest, 7, 0, 0, vbs)
}

func TestReadOnlyRefusesWrites(t *testing.T) {
	p := NewReadOnly()
	if !p.ReadOnly() {
		t.Error("ReadOnly() = false")
	}
	if p.Allowed(setPDU(t, "1.3.6.1.4.1.99.1.0")) {
		t.Error("read-only policy allowed a SET")
	}
	// reads are untouched
	for _, typ := range []uint8{msg.PDUGetRequest, msg.PDUGetNextRequest, msg.PDUGetBulkRequest} {
		if !p.Allowed(msg.BuildPDU(typ, 1, 0, 0, nil)) {
			t.Errorf("read-only policy blocked PDU type %#x", typ)
		}
	}
}

func TestWritePolicyRules(t *testing.T) {
	// allow writes under the writable subtree, deny everything else,
	// except the explicitly denied sub-subtree inside the allowed one.
	p, err := NewWritePolicy(false, []WriteRule{
		{OID: "1.3.6.1.4.1.99.1", Allow: true},
		{OID: "1.3.6.1.4.1.99.1.9", Allow: false},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		oids []string
		want bool
	}{
		{"inside allowed subtree", []string{"1.3.6.1.4.1.99.1.0"}, true},
		{"exactly the allowed root", []string{"1.3.6.1.4.1.99.1"}, true},
		{"two objects both allowed", []string{"1.3.6.1.4.1.99.1.2", "1.3.6.1.4.1.99.1.3"}, true},
		{"outside any rule, default deny", []string{"1.3.6.1.4.1.99.2.0"}, false},
		{"inside explicitly denied subtree", []string{"1.3.6.1.4.1.99.1.9.4"}, false},
		// deny-overrides: one allowed object cannot rescue a SET that
		// also touches a forbidden one
		{"straddles allow and deny", []string{"1.3.6.1.4.1.99.1.2", "1.3.6.1.4.1.99.1.9.4"}, false},
		// allow-must-cover: every object must be covered by an allow
		{"partially covered", []string{"1.3.6.1.4.1.99.1.2", "1.3.6.1.4.1.77.1"}, false},
		// arc boundary: ...99.1 must not cover ...99.10
		{"sibling numeric prefix", []string{"1.3.6.1.4.1.99.10.1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Allowed(setPDU(t, tc.oids...)); got != tc.want {
				t.Errorf("Allowed(%v) = %v, want %v", tc.oids, got, tc.want)
			}
		})
	}
}

func TestWritePolicyDefaultAllow(t *testing.T) {
	p, err := NewWritePolicy(true, []WriteRule{{OID: "1.3.6.1.4.1.99.9", Allow: false}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(setPDU(t, "1.3.6.1.4.1.42.1")) {
		t.Error("unmatched write rejected under default allow")
	}
	if p.Allowed(setPDU(t, "1.3.6.1.4.1.99.9.1")) {
		t.Error("deny rule lost against default allow")
	}
}

func TestWritePolicyValidation(t *testing.T) {
	// no rules + default deny is what read_only is for
	if _, err := NewWritePolicy(false, nil); err == nil {
		t.Error("empty default-deny policy accepted")
	}
	if _, err := NewWritePolicy(false, []WriteRule{{OID: "nope", Allow: true}}); err == nil {
		t.Error("invalid rule OID accepted")
	}
	var re *RuleError
	if _, err := NewWritePolicy(false, []WriteRule{{OID: "1.3.6.1", Allow: true}, {OID: "bad", Allow: true}}); err == nil {
		t.Error("second invalid rule accepted")
	} else if !asRuleError(err, &re) || re.Index != 1 {
		t.Errorf("RuleError index not reported: %v", err)
	}
	// a leading dot is tolerated and canonicalized
	p, err := NewWritePolicy(true, []WriteRule{{OID: ".1.3.6.1.4.1.99", Allow: false}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(setPDU(t, "1.3.6.1.4.1.99.1")) {
		t.Error("canonicalized rule did not match")
	}
}

func asRuleError(err error, out **RuleError) bool {
	re, ok := err.(*RuleError)
	if ok {
		*out = re
	}
	return ok
}

func TestWritePolicyCannotDecodeWrite(t *testing.T) {
	p, _ := NewWritePolicy(true, nil)
	// SET with an empty varbind list cannot be authorized
	if p.Allowed(msg.BuildPDU(msg.PDUSetRequest, 1, 0, 0, nil)) {
		t.Error("SET without varbinds was allowed")
	}
	// a varbind that is not a SEQUENCE is malformed
	bad := msg.BuildPDU(msg.PDUSetRequest, 1, 0, 0, msg.AppendTLV(nil, 0x04, []byte{1, 2, 3}))
	if p.Allowed(bad) {
		t.Error("SET with malformed varbind list was allowed")
	}
	// undecodable PDU
	if p.Allowed([]byte{msg.PDUSetRequest, 0x05}) {
		t.Error("undecodable SET was allowed")
	}
}

func TestNilPolicyAllowsEverything(t *testing.T) {
	var p *Policy
	ip := net.ParseIP("10.1.2.3")
	if !p.AllowClient(ip) || !p.AllowRate(ip) || !p.AllowWrite(setPDU(t, "1.3.6.1.1")) {
		t.Error("nil policy restricted something")
	}
	if p.ReadOnly() || p.WritePolicyRules() != 0 {
		t.Error("nil policy reports a policy")
	}
}

func TestHolderSwap(t *testing.T) {
	h := NewHolder(nil)
	ip := net.ParseIP("10.1.2.3")
	if !h.Get().AllowWrite(setPDU(t, "1.3.6.1.1")) {
		t.Fatal("initial nil policy restricted a write")
	}
	h.Store(NewHolder(&Policy{writes: NewReadOnly()}).Get())
	if h.Get().AllowWrite(setPDU(t, "1.3.6.1.1")) {
		t.Fatal("swapped-in read-only policy did not take effect")
	}
	h.Store(nil)
	if !h.Get().AllowWrite(setPDU(t, "1.3.6.1.1")) {
		t.Fatal("nil store did not restore allow-all")
	}
	// a nil holder reads as no policy
	var nilH *Holder
	if nilH.Get() != nil {
		t.Fatal("nil holder returned a policy")
	}
	var nilP *Policy = nilH.Get()
	if !nilP.AllowClient(ip) {
		t.Fatal("nil holder policy restricted a client")
	}
}

func TestLimitPerClient(t *testing.T) {
	l := NewLimit(3)
	if l == nil {
		t.Fatal("NewLimit(3) = nil")
	}
	now := time.Unix(1000, 0)
	l.nowFn = func() time.Time { return now }

	a := net.ParseIP("10.0.0.1")
	b := net.ParseIP("10.0.0.2")
	for i := 0; i < 3; i++ {
		if !l.Allow(a) {
			t.Fatalf("request %d from a rejected", i+1)
		}
	}
	if l.Allow(a) {
		t.Error("4th request from a admitted past the limit")
	}
	// another client has its own bucket
	if !l.Allow(b) {
		t.Error("first request from b rejected (shared bucket?)")
	}
	// one second later the bucket has refilled
	now = now.Add(time.Second)
	if !l.Allow(a) {
		t.Error("bucket did not refill after one second")
	}
	if l.Len() != 2 {
		t.Errorf("Len() = %d, want 2", l.Len())
	}
}

func TestLimitSweepsIdleClients(t *testing.T) {
	l := NewLimit(1)
	now := time.Unix(2000, 0)
	l.nowFn = func() time.Time { return now }

	for i := 0; i < 100; i++ {
		l.Allow(net.ParseIP("10.0.0." + itoa(i+1)))
	}
	if l.Len() != 100 {
		t.Fatalf("Len() = %d, want 100", l.Len())
	}
	now = now.Add(limitSweepEvery + limitIdleAfter + time.Second)
	l.Allow(net.ParseIP("10.0.9.9"))
	if l.Len() != 1 {
		t.Errorf("Len() after sweep = %d, want 1", l.Len())
	}
}

func TestLimitNilIsUnlimited(t *testing.T) {
	l := NewLimit(0)
	if l != nil {
		t.Fatal("NewLimit(0) should be nil")
	}
	for i := 0; i < 1000; i++ {
		if !l.Allow(net.ParseIP("10.0.0.1")) {
			t.Fatal("nil limit rejected a request")
		}
	}
}

func TestLimitFailsClosedWhenFull(t *testing.T) {
	l := NewLimit(1)
	now := time.Unix(3000, 0)
	l.nowFn = func() time.Time { return now }
	for i := 0; i < limitMaxBuckets; i++ {
		// one ip per bucket, distinct /16s to dodge IPv4 parsing limits
		l.Allow(net.IPv4(byte(10+i/65536), byte(i/256), byte(i%256), 1))
	}
	if l.Len() != limitMaxBuckets {
		t.Fatalf("Len() = %d, want %d", l.Len(), limitMaxBuckets)
	}
	if l.Allow(net.ParseIP("198.51.100.7")) {
		t.Error("new client admitted with a full bucket table")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func TestCheckOrder(t *testing.T) {
	p, err := New([]string{"10.0.0.0/24"}, 1, NewReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	// not on the allow-list: no rate token is consumed either
	if got := p.Check(net.ParseIP("192.0.2.1")); got != DeniedClient {
		t.Errorf("Check(off-list) = %v, want DeniedClient", got)
	}
	if got := p.Check(net.ParseIP("10.0.0.1")); got != Allowed {
		t.Errorf("Check(on-list) = %v, want Allowed", got)
	}
	if got := p.Check(net.ParseIP("10.0.0.1")); got != DeniedRate {
		t.Errorf("Check(second request) = %v, want DeniedRate", got)
	}
	// the write check is separate from admission
	if p.AllowWrite(setPDU(t, "1.3.6.1.4.1.99.1")) {
		t.Error("read-only policy allowed a write through Check")
	}
}

func TestIPOf(t *testing.T) {
	if ip := IPOf(&net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 161}); !ip.Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("IPOf(udp) = %v", ip)
	}
	if ip := IPOf(&net.TCPAddr{IP: net.ParseIP("10.1.2.4"), Port: 1}); !ip.Equal(net.ParseIP("10.1.2.4")) {
		t.Errorf("IPOf(tcp) = %v", ip)
	}
	if ip := IPOf(nil); ip != nil {
		t.Errorf("IPOf(nil) = %v, want nil", ip)
	}
}

func TestDenyResponse(t *testing.T) {
	req := setPDU(t, "1.3.6.1.4.1.99.1.0")
	out, ok := DenyResponse(msg.Version2c, []byte("secret"), req)
	if !ok {
		t.Fatal("DenyResponse failed on a valid SET")
	}
	ver, community, pdu, err := msg.SplitV1V2c(out)
	if err != nil {
		t.Fatalf("split response: %v", err)
	}
	if ver != msg.Version2c || string(community) != "secret" {
		t.Errorf("response version/community = %d/%q", ver, community)
	}
	typ, f, err := msg.ParsePDU(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if typ != msg.PDUGetResponse {
		t.Errorf("PDU type = %#x, want GetResponse", typ)
	}
	if f.ErrStatus != msg.ErrStatusNotWritable {
		t.Errorf("errStatus = %d, want %d", f.ErrStatus, msg.ErrStatusNotWritable)
	}
	if f.ReqID != 7 {
		t.Errorf("req-id = %d, want 7 (echoed)", f.ReqID)
	}

	// v1 cannot express notWritable: RFC 2576 maps it to noSuchName
	out, ok = DenyResponse(msg.Version1, []byte("public"), req)
	if !ok {
		t.Fatal("DenyResponse failed for v1")
	}
	_, _, pdu, _ = msg.SplitV1V2c(out)
	_, f, _ = msg.ParsePDU(pdu)
	if f.ErrStatus != msg.ErrStatusNoSuchName || f.ErrIndex != 1 {
		t.Errorf("v1 errStatus/errIndex = %d/%d, want 2/1", f.ErrStatus, f.ErrIndex)
	}

	// an undecodable request has no sensible answer
	if _, ok := DenyResponse(msg.Version2c, nil, []byte{0xA3, 0x05}); ok {
		t.Error("DenyResponse answered an undecodable PDU")
	}
}
