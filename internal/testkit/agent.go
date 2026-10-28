package testkit

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

// BER tags a fake device answers with (SNMPv2 exceptions included).
const (
	TagInteger        = 0x02
	TagOctetString    = 0x04
	TagOID            = 0x06
	TagIpAddress      = 0x40
	TagCounter32      = 0x41
	TagGauge32        = 0x42
	TagTimeTicks      = 0x43
	TagCounter64      = 0x46
	TagNoSuchObject   = 0x80
	TagNoSuchInstance = 0x81
	TagEndOfMibView   = 0x82
)

// Entry is one object in the fake device's MIB.
type Entry struct {
	OID   string // dotted, no leading dot
	Type  byte
	Value []byte // raw content (use the Append* helpers in msg)
}

// Request is one datagram the fake device received, decoded enough to make
// assertions about what the proxy actually forwarded.
type Request struct {
	Version   int
	Community string
	PDUType   uint8
	ReqID     int32
	OIDs      []string
	Raw       []byte
}

// AgentOptions tunes device behaviour for a specific test.
type AgentOptions struct {
	// Delay postpones every answer (for timeout/retry tests).
	Delay time.Duration
	// IgnoreSETs makes the device silently swallow SET requests, which is
	// how a read-only legacy device behaves.
	IgnoreSETs bool
	// Community, when set, is the only community the device answers.
	Community string
}

// Agent is a fake SNMPv1/v2c device on loopback. It is a *device*, not a
// proxy: it implements real GETNEXT/GETBULK semantics and real exceptions,
// because a device that echoes requests back hides proxy bugs.
type Agent struct {
	conn    net.PacketConn
	opts    AgentOptions
	entries []Entry

	mu       sync.Mutex
	requests []Request
	sets     atomic.Int32
	gets     atomic.Int32
}

// DefaultMIB is a small but realistic device: a string, an OID, a name, an
// uptime and a writable-looking integer.
func DefaultMIB() []Entry {
	return []Entry{
		{OID: "1.3.6.1.2.1.1.1.0", Type: TagOctetString, Value: []byte("testkit fake agent v1")},
		{OID: "1.3.6.1.2.1.1.2.0", Type: TagOID, Value: mustOID("1.3.6.1.4.1.8072.3.2.10")},
		{OID: "1.3.6.1.2.1.1.3.0", Type: TagTimeTicks, Value: msg.AppendUint32(nil, 424242)[2:]},
		{OID: "1.3.6.1.2.1.1.5.0", Type: TagOctetString, Value: []byte("testkit")},
		{OID: "1.3.6.1.4.1.99.1.1.0", Type: TagInteger, Value: msg.AppendInteger(nil, -7)[2:]},
	}
}

// NewAgent starts a fake device on an ephemeral loopback port and closes it
// at test end.
func NewAgent(t testing.TB, opts AgentOptions, entries ...Entry) *Agent {
	t.Helper()
	if len(entries) == 0 {
		entries = DefaultMIB()
	}
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return compareOIDs(sorted[i].OID, sorted[j].OID) < 0 })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testkit: fake agent bind: %v", err)
	}
	a := &Agent{conn: conn, opts: opts, entries: sorted}
	go a.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return a
}

// Addr is the device's host:port.
func (a *Agent) Addr() string { return a.conn.LocalAddr().String() }

// Requests returns a copy of everything the device received.
func (a *Agent) Requests() []Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Request, len(a.requests))
	copy(out, a.requests)
	return out
}

// SETs is how many SET requests reached the device (the standard oracle for
// "the policy refused this before it left the proxy").
func (a *Agent) SETs() int { return int(a.sets.Load()) }

// GETs is how many GET-class requests reached the device.
func (a *Agent) GETs() int { return int(a.gets.Load()) }

// Forget discards recorded requests without restarting the device.
func (a *Agent) Forget() {
	a.mu.Lock()
	a.requests = nil
	a.mu.Unlock()
}

func (a *Agent) serve() {
	buf := make([]byte, 65536)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		dg := append([]byte(nil), buf[:n]...)
		go a.handle(dg, from)
	}
}

func (a *Agent) handle(dg []byte, from net.Addr) {
	if a.opts.Delay > 0 {
		time.Sleep(a.opts.Delay)
	}
	version, community, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		return
	}
	if a.opts.Community != "" && string(community) != a.opts.Community {
		return // wrong community: a real device stays silent
	}
	_, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		return
	}
	vbs, err := msg.ParseVarbinds(fields.Varbinds)
	if err != nil {
		return
	}
	oids := make([]string, len(vbs))
	for i, vb := range vbs {
		oids[i] = vb.OID
	}
	a.mu.Lock()
	a.requests = append(a.requests, Request{
		Version: version, Community: string(community), PDUType: pdu[0],
		ReqID: fields.ReqID, OIDs: oids, Raw: dg,
	})
	a.mu.Unlock()

	pduType := pdu[0]
	var answer []msg.Varbind
	var errStatus, errIndex int32

	switch pduType {
	case msg.PDUGetRequest:
		a.gets.Add(1)
		for _, vb := range vbs {
			if e, ok := a.lookup(vb.OID); ok {
				answer = append(answer, e)
			} else {
				answer = append(answer, msg.Varbind{OID: vb.OID, Type: TagNoSuchInstance})
			}
		}
	case msg.PDUGetNextRequest:
		a.gets.Add(1)
		for _, vb := range vbs {
			if e, ok := a.next(vb.OID); ok {
				answer = append(answer, e)
			} else {
				answer = append(answer, msg.Varbind{OID: vb.OID, Type: TagEndOfMibView})
			}
		}
	case msg.PDUGetBulkRequest:
		a.gets.Add(1)
		nonRepeaters := int(fields.ErrStatus) // RFC 3416: non-repeaters reuse these fields
		repeaters := int(fields.ErrIndex)
		if nonRepeaters < 0 {
			nonRepeaters = 0
		}
		if repeaters <= 0 {
			repeaters = 1
		}
		var repeatOIDs []string
		for i, vb := range vbs {
			if i < nonRepeaters {
				if e, ok := a.next(vb.OID); ok {
					answer = append(answer, e)
				} else {
					answer = append(answer, msg.Varbind{OID: vb.OID, Type: TagEndOfMibView})
				}
				continue
			}
			repeatOIDs = append(repeatOIDs, vb.OID)
		}
		cursors := append([]string(nil), repeatOIDs...)
		for r := 0; r < repeaters; r++ {
			progressed := false
			for i, cur := range cursors {
				e, ok := a.next(cur)
				if !ok {
					answer = append(answer, msg.Varbind{OID: cur, Type: TagEndOfMibView})
					continue
				}
				answer = append(answer, e)
				cursors[i] = e.OID
				progressed = true
			}
			if !progressed {
				break
			}
		}
	case msg.PDUSetRequest:
		a.sets.Add(1)
		if a.opts.IgnoreSETs {
			return
		}
		// Echo the requested objects back; the proxy relays the answer
		// verbatim, so the shape is what matters here.
		answer = append(answer, vbs...)
	default:
		return
	}

	resp := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, errStatus, errIndex, msg.BuildVarbinds(answer))
	out, err := msg.BuildV1V2c(version, community, resp)
	if err != nil {
		return
	}
	_, _ = a.conn.WriteTo(out, from)
}

func (a *Agent) lookup(oid string) (msg.Varbind, bool) {
	for _, e := range a.entries {
		if e.OID == oid {
			return msg.Varbind{OID: e.OID, Type: e.Type, Value: e.Value}, true
		}
	}
	return msg.Varbind{}, false
}

// next implements GETNEXT: the first object strictly greater than oid.
func (a *Agent) next(oid string) (msg.Varbind, bool) {
	for _, e := range a.entries {
		if compareOIDs(e.OID, oid) > 0 {
			return msg.Varbind{OID: e.OID, Type: e.Type, Value: e.Value}, true
		}
	}
	return msg.Varbind{}, false
}

// compareOIDs compares two dotted OIDs numerically, arc by arc. Comparing
// the strings is wrong (".10" sorts before ".7"), which is why every
// GETNEXT/GETBULK implementation needs this helper — the SNMP metrics agent
// had the same bug.
func compareOIDs(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "."), ".")
	bs := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.ParseUint(as[i], 10, 32)
		bi, berr := strconv.ParseUint(bs[i], 10, 32)
		if aerr != nil || berr != nil {
			return strings.Compare(as[i], bs[i])
		}
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

func mustOID(dotted string) []byte {
	enc, err := msg.EncodeOID(dotted)
	if err != nil {
		panic(fmt.Sprintf("testkit: bad OID %q: %v", dotted, err))
	}
	return enc
}

// Uint32Content strips the TLV header from an AppendUint32 result, giving
// the raw content a Varbind needs.
func Uint32Content(v uint32) []byte { return msg.AppendUint32(nil, v)[2:] }

// IntegerContent is Uint32Content for signed integers.
func IntegerContent(v int32) []byte { return msg.AppendInteger(nil, v)[2:] }
