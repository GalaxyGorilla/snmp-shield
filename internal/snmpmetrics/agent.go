// Package snmpmetrics exposes the proxy's Prometheus instruments over
// SNMP: a small read-only SNMPv2c agent (GET/GETNEXT) for health polling
// and a v2c trap sender for tunnel lifecycle events. This lets an
// SNMP-native monitoring system watch the proxy without the HTTP
// metrics endpoint.
package snmpmetrics

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GalaxyGorilla/snmp-proxy/internal/msg"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// errNotAVarbind marks a malformed varbind sequence.
var errNotAVarbind = errors.New("snmpmetrics: varbind is not {OID, value}")

// MIB layout (all under BaseOID, default .1.3.6.1.4.1.58427.1):
//
//	<Base>.1   product         OCTET STRING, fixed "snmp-proxy"
//	<Base>.2   version         OCTET STRING
//	<Base>.3   role            OCTET STRING
//	<Base>.4   securityMode    OCTET STRING
//	<Base>.5   tunnelMode      OCTET STRING
//	<Base>.6   tunnelEndpoints OCTET STRING, comma-separated
//	<Base>.7   uptimeSecs      INTEGER, seconds since agent start
//	<Base>.10  tunnelUp        INTEGER, 1 when the tunnel session is up
//	<Base>.11  tunnelEndpoint  OCTET STRING, current peer
//	<Base>.20.<n> counters     INTEGER, 1-based row per CounterList order
//	<Base>.30  latencyCount    INTEGER, forwarded requests observed
//	<Base>.31  latencySum      INTEGER, cumulative seconds, truncated
//
// Events subtree (traps):
//
//	<Base>.2.1  tunnel established (failover flag distinguishes HA switch)
//	<Base>.2.2  tunnel lost
//	<Base>.2.3  HA failover to another endpoint

// Agent is a tiny read-only SNMPv2c agent exposing proxy health, plus a
// v2c trap sender for tunnel lifecycle events.
type Agent struct {
	community string
	base      string
	log       *zap.Logger

	role        string
	secMode     string
	tunnelMode  string
	endpoints   string
	version     string
	product     string
	startedAt   time.Time
	tunnelUp    atomic.Bool
	curEndpoint atomic.Value // string

	// counters is the ordered counter table: MIB arc .20.<n+1> maps to
	// row n. Read via the prometheus collector interface (ToFloat64
	// semantics without importing testutil).
	counters []prometheus.Counter
	latency  prometheus.Histogram

	mu       sync.Mutex
	listener *net.UDPConn
}

// Config describes the agent identity and wiring.
type Config struct {
	Community  string // SNMPv2c community (default "public")
	BaseOID    string // MIB base (default ".1.3.6.1.4.1.58427.1")
	Version    string // product version string
	Role       string // proxy role (manager/agent/gateway)
	SecMode    string // security.mode
	TunnelMode string // tunnel transport ("" for gateway roles)
	Endpoints  string // comma-separated tunnel endpoints ("" for gateway)
}

// New builds the metrics agent. counters/latency are the prometheus
// instruments exposed under .20.x/.30/.31 (nil entries are skipped with
// their arc reserved — keep the row order stable).
func New(cfg Config, counters []prometheus.Counter, latency prometheus.Histogram, log *zap.Logger) *Agent {
	if cfg.Community == "" {
		cfg.Community = "public"
	}
	if cfg.BaseOID == "" {
		cfg.BaseOID = ".1.3.6.1.4.1.58427.1"
	}
	// Normalize: the dotted accessor form always carries a leading dot
	// (".1.3.6..."), but EncodeOID rejects it — strip for encoding.
	cfg.BaseOID = strings.TrimPrefix(cfg.BaseOID, ".")
	a := &Agent{
		community:  cfg.Community,
		base:       cfg.BaseOID,
		log:        log,
		role:       cfg.Role,
		secMode:    cfg.SecMode,
		tunnelMode: cfg.TunnelMode,
		endpoints:  cfg.Endpoints,
		version:    cfg.Version,
		product:    "snmp-proxy",
		startedAt:  time.Now(),
		counters:   counters,
		latency:    latency,
	}
	a.curEndpoint.Store("")
	return a
}

// SetTunnelUp updates the tunnel state scalars.
func (a *Agent) SetTunnelUp(up bool, endpoint string) {
	a.tunnelUp.Store(up)
	a.curEndpoint.Store(endpoint)
}

// Serve binds the SNMP listener on addr and answers GET/GETNEXT until
// stop is closed. It is intended to run in its own goroutine.
func (a *Agent) Serve(addr string, stop <-chan struct{}) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("snmp metrics listen: %w", err)
	}
	a.mu.Lock()
	a.listener = pc.(*net.UDPConn)
	a.mu.Unlock()

	go func() {
		<-stop
		_ = pc.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			return err
		}
		dg := make([]byte, n)
		copy(dg, buf[:n])
		if resp := a.handle(dg); resp != nil {
			if _, werr := pc.WriteTo(resp, raddr); werr != nil && a.log != nil {
				a.log.Debug("snmp metrics write", zap.Error(werr))
			}
		}
	}
}

// handle parses one SNMP v1/v2c datagram and builds the GetResponse.
// Anything malformed, wrong-community or non-GET/GETNEXT is ignored
// (no response).
func (a *Agent) handle(dg []byte) []byte {
	version, community, pdu, err := msg.SplitV1V2c(dg)
	if err != nil {
		return nil
	}
	if string(community) != a.community {
		return nil
	}
	_ = version
	pduType, fields, err := msg.ParsePDU(pdu)
	if err != nil {
		return nil
	}
	switch pduType {
	case msg.PDUGetRequest:
		return a.respondGet(fields)
	case msg.PDUGetNextRequest:
		return a.respondNext(fields)
	default:
		return nil // SET etc: not supported, no response
	}
}

// varbind is one resolved MIB object: its dotted OID and the raw value
// TLV.
type varbind struct {
	oid string
	tlv []byte // complete value TLV
}

// resolve answers one exact OID; nil when unknown.
func (a *Agent) resolve(oid string) *varbind {
	str := func(s string) *varbind {
		return &varbind{oid: oid, tlv: msg.AppendOctetString(nil, []byte(s))}
	}
	intv := func(v int64) *varbind {
		return &varbind{oid: oid, tlv: msg.AppendInteger(nil, int32(v))}
	}
	switch oid {
	case a.base + ".1":
		return str(a.product)
	case a.base + ".2":
		return str(a.version)
	case a.base + ".3":
		return str(a.role)
	case a.base + ".4":
		return str(a.secMode)
	case a.base + ".5":
		return str(a.tunnelMode)
	case a.base + ".6":
		return str(a.endpoints)
	case a.base + ".7":
		return intv(int64(time.Since(a.startedAt) / time.Second))
	case a.base + ".10":
		if a.tunnelUp.Load() {
			return intv(1)
		}
		return intv(0)
	case a.base + ".11":
		return str(a.curEndpoint.Load().(string))
	case a.base + ".30":
		if a.latency == nil {
			return intv(0)
		}
		m := &dto.Metric{}
		if a.latency.Write(m) != nil || m.Histogram == nil || m.Histogram.SampleCount == nil {
			return intv(0)
		}
		return intv(int64(*m.Histogram.SampleCount))
	case a.base + ".31":
		if a.latency == nil {
			return intv(0)
		}
		m := &dto.Metric{}
		if a.latency.Write(m) != nil || m.Histogram == nil || m.Histogram.SampleSum == nil {
			return intv(0)
		}
		return intv(int64(*m.Histogram.SampleSum))
	}
	// counters: .20.<n>, 1-based
	if n, ok := counterArc(a.base+".20.", oid); ok {
		i := int(n) - 1
		if i < 0 || i >= len(a.counters) || a.counters[i] == nil {
			return nil
		}
		m := &dto.Metric{}
		if a.counters[i].Write(m) != nil || m.Counter == nil {
			return nil
		}
		return intv(int64(m.Counter.GetValue()))
	}
	return nil
}

// counterArc parses the ".20.<n>" row of oid; ok when oid is exactly
// base+"20."+n with n >= 1.
func counterArc(prefix, oid string) (int64, bool) {
	if len(oid) <= len(prefix) || oid[:len(prefix)] != prefix {
		return 0, false
	}
	n, err := strconv.ParseInt(oid[len(prefix):], 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// nextAfter returns the next MIB object strictly after oid, or nil at
// the end of the table. Comparison is arc-by-arc (numeric), not
// lexicographic: dotted strings sort ".10" before ".7".
func (a *Agent) nextAfter(oid string) *varbind {
	var req []uint64
	if parsed, err := parseArcs(oid); err == nil {
		req = parsed
	}
	for _, o := range a.objectIDs() {
		if arcs, err := parseArcs(o); err != nil || !arcsAfter(arcs, req) {
			continue
		}
		return a.resolve(o)
	}
	return nil
}

// parseArcs splits a dotted OID into its numeric arcs.
func parseArcs(s string) ([]uint64, error) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, errNotAVarbind
	}
	parts := strings.Split(s, ".")
	arcs := make([]uint64, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, errNotAVarbind
		}
		arcs = append(arcs, v)
	}
	return arcs, nil
}

// arcsAfter reports whether a sorts strictly after b, arc-by-arc
// (numeric). A longer OID sharing b's prefix sorts after b.
func arcsAfter(a, b []uint64) bool {
	for i := range a {
		if i >= len(b) {
			return true // a extends b: a is deeper => after
		}
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false // equal or a is a prefix of b => not after
}

// objectIDs lists every readable OID in ascending order (counters last,
// their arcs ascending).
func (a *Agent) objectIDs() []string {
	out := []string{
		a.base + ".1", a.base + ".2", a.base + ".3", a.base + ".4",
		a.base + ".5", a.base + ".6", a.base + ".7",
		a.base + ".10", a.base + ".11",
	}
	for i := range a.counters {
		out = append(out, a.base+".20."+strconv.Itoa(i+1))
	}
	out = append(out, a.base+".30", a.base+".31")
	return out
}

// respondGet builds the GetResponse for fields' varbinds; unknown OIDs
// get noSuchInstance semantics by simply returning nothing? No: SNMPv2c
// wants an exception. We answer errStatus=2 (noSuchName) SNMPv1-style,
// which both v1 and v2c managers understand.
func (a *Agent) respondGet(fields msg.PDUFields) []byte {
	var vb []byte
	for rest := fields.Varbinds; len(rest) > 0; {
		tag, content, r, err := msg.NextTLV(rest)
		if err != nil || tag != 0x30 {
			return nil
		}
		rest = r
		oidBytes, _, err := splitVarbind(content)
		if err != nil {
			return nil
		}
		oid, err := msg.DecodeOID(oidBytes)
		if err != nil {
			return nil
		}
		res := a.resolve(oid)
		if res == nil {
			// noSuchName: rebuild with error status at this index
			return a.errResponse(fields, 2, vbIndex(fields.Varbinds, oid))
		}
		vb = msg.AppendTLV(vb, 0x30, append(msg.AppendOIDTLV(nil, oidBytes), res.tlv...))
	}
	return a.buildResponse(fields, vb)
}

// respondNext builds the GetResponse for a GETNEXT: each varbind's OID
// is replaced with its lexicographic successor; endOfMibView (0x80) when
// the table is exhausted.
func (a *Agent) respondNext(fields msg.PDUFields) []byte {
	var vb []byte
	for rest := fields.Varbinds; len(rest) > 0; {
		tag, content, r, err := msg.NextTLV(rest)
		if err != nil || tag != 0x30 {
			return nil
		}
		rest = r
		oidBytes, _, err := splitVarbind(content)
		if err != nil {
			return nil
		}
		oid, err := msg.DecodeOID(oidBytes)
		if err != nil {
			return nil
		}
		res := a.nextAfter(oid)
		if res == nil {
			// endOfMibView per RFC 1905: value = {0x80, 0x00}
			vb = msg.AppendTLV(vb, 0x30, append(msg.AppendOIDTLV(nil, oidBytes), 0x80, 0x00))
			continue
		}
		nextBytes, err := msg.EncodeOID(res.oid)
		if err != nil {
			return nil
		}
		vb = msg.AppendTLV(vb, 0x30, append(msg.AppendOIDTLV(nil, nextBytes), res.tlv...))
	}
	return a.buildResponse(fields, vb)
}

// splitVarbind splits a varbind SEQUENCE content into the OID TLV
// content (raw sub-ids) and the remaining value TLV.
func splitVarbind(content []byte) (oidBytes, valueTLV []byte, err error) {
	tag, oidContent, rest, err := msg.NextTLV(content)
	if err != nil {
		return nil, nil, err
	}
	if tag != 0x06 {
		return nil, nil, errNotAVarbind
	}
	return oidContent, rest, nil
}

// vbIndex returns the 1-based position of oid within the varbind list.
func vbIndex(vb []byte, oid string) int32 {
	idx := int32(0)
	for rest := vb; len(rest) > 0; {
		tag, content, r, err := msg.NextTLV(rest)
		if err != nil || tag != 0x30 {
			break
		}
		rest = r
		idx++
		oidBytes, _, err := splitVarbind(content)
		if err != nil {
			continue
		}
		d, err := msg.DecodeOID(oidBytes)
		if err == nil && d == oid {
			return idx
		}
	}
	return 1
}

// buildResponse assembles the GetResponse PDU datagram (v2c).
func (a *Agent) buildResponse(fields msg.PDUFields, varbinds []byte) []byte {
	pdu := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, 0, 0, varbinds)
	out, err := msg.BuildV1V2c(msg.Version2c, []byte(a.community), pdu)
	if err != nil {
		return nil
	}
	return out
}

// errResponse assembles a GetResponse with an error status set (SNMPv1
// noSuchName semantics, understood by all managers).
func (a *Agent) errResponse(fields msg.PDUFields, status, index int32) []byte {
	pdu := msg.BuildPDU(msg.PDUGetResponse, fields.ReqID, status, index, nil)
	out, err := msg.BuildV1V2c(msg.Version2c, []byte(a.community), pdu)
	if err != nil {
		return nil
	}
	return out
}

// SendTrap emits a v2c notification with the given trap OID (under the
// events subtree) plus sysUpTime.0 to sink. Fire and forget; errors are
// logged at debug level. When the agent serves no MIB listener, a
// dedicated ephemeral socket sends the trap.
func (a *Agent) SendTrap(trapOID string, sink net.Addr) error {
	if sink == nil {
		return nil
	}
	var vb []byte
	// sysUpTime.0 TimeTicks first, then snmpTrapOID.0.
	vb = msg.AppendTLV(vb, 0x30, append(
		msg.AppendOIDTLV(nil, msg.OIDSysUpTime),
		msg.AppendTimeTicks(nil, uint32(time.Since(a.startedAt)/time.Second))...,
	))
	trapBytes, err := msg.EncodeOID(trapOID)
	if err != nil {
		return err
	}
	vb = msg.AppendTLV(vb, 0x30, append(
		msg.AppendOIDTLV(nil, msg.OIDSnmpTrapOID),
		msg.AppendOIDTLV(nil, trapBytes)...,
	))
	pdu := msg.BuildPDU(msg.PDUSNMPv2Trap, 0, 0, 0, vb)
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte(a.community), pdu)
	if err != nil {
		return err
	}
	if conn := a.currentConn(); conn != nil {
		_, err = conn.WriteTo(dg, sink)
		return err
	}
	// No MIB listener: send from a dedicated ephemeral socket (trap-only
	// configuration).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	_, err = pc.WriteTo(dg, sink)
	return err
}

// currentConn returns the bound listener socket (used as the trap source
// so replies correlate). Returns a nil net.PacketConn when no listener
// is bound (checked with an explicit nil pointer test, not an interface
// comparison — a nil *net.UDPConn inside a net.PacketConn interface is
// non-nil).
func (a *Agent) currentConn() net.PacketConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listener == nil {
		return nil
	}
	return a.listener
}
