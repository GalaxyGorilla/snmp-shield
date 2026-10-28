package conformance

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// goSnmpPeer is gosnmp as an in-process peer.
//
// It is the one peer that is always present (it is a module dependency), so
// the conformance matrix never silently becomes empty on a bare machine.
// Being in-process makes it the least independent of the four, which is
// exactly why it must not be the only one.
type goSnmpPeer struct{}

func newGoSnmpPeer() *goSnmpPeer { return &goSnmpPeer{} }

func (p *goSnmpPeer) Name() string  { return "gosnmp" }
func (p *goSnmpPeer) Stack() string { return "gosnmp v1.45.0 (Go, in-process)" }
func (p *goSnmpPeer) Unavailable() string {
	return ""
}

func (p *goSnmpPeer) Run(ctx context.Context, req Request) (Result, error) {
	host, portStr, err := net.SplitHostPort(req.Target)
	if err != nil {
		return Result{ErrorKind: KindUsage, Error: err.Error()}, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Result{ErrorKind: KindUsage, Error: err.Error()}, nil
	}
	timeout := time.Duration(req.Timeout * float64(time.Second))
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Transport: "udp",
		Timeout:   timeout,
		Retries:   req.Retries,
		Context:   ctx,
	}
	switch req.Version {
	case "1":
		snmp.Version = gosnmp.Version1
		snmp.Community = req.Community
	case "3":
		snmp.Version = gosnmp.Version3
		snmp.SecurityModel = gosnmp.UserSecurityModel
		level, err := goSnmpLevel(req)
		if err != nil {
			return Result{ErrorKind: KindUsage, Error: err.Error()}, nil
		}
		snmp.MsgFlags = level.flags
		snmp.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 req.User,
			AuthenticationProtocol:   level.authProto,
			AuthenticationPassphrase: req.Auth,
			PrivacyProtocol:          level.privProto,
			PrivacyPassphrase:        req.Priv,
		}
	default:
		snmp.Version = gosnmp.Version2c
		snmp.Community = req.Community
	}

	// A notification sender is authoritative for its OWN engine: it has an
	// engineID, boots and time, and does not discover the receiver. Left
	// empty, gosnmp performs an RFC 3414 discovery handshake against the
	// trap receiver, which correctly ignores discovery probes (a trap
	// listener has no engine to announce) — the notification then never
	// leaves and looks like a vendor timeout.
	if req.Verb == VerbTrap || req.Verb == VerbInform {
		if usp, ok := snmp.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok &&
			usp.AuthoritativeEngineID == "" {
			usp.AuthoritativeEngineID = notificationEngineID(req.User)
			usp.AuthoritativeEngineBoots = 7
			usp.AuthoritativeEngineTime = 7
		}
	}

	if err := snmp.Connect(); err != nil {
		return goSnmpResult(nil, err), nil
	}
	defer snmp.Conn.Close()

	if req.Verb == VerbTrap || req.Verb == VerbInform {
		trap, perr := goSnmpTrap(req)
		if perr != nil {
			return Result{ErrorKind: KindUsage, Error: perr.Error()}, nil
		}
		_, terr := snmp.SendTrap(trap)
		if terr != nil {
			return goSnmpResult(nil, terr), nil
		}
		return Result{OK: true}, nil
	}

	if req.Verb != VerbSet && len(req.OIDs) == 0 {
		return Result{ErrorKind: KindUsage, Error: "no OIDs"}, nil
	}

	switch req.Verb {
	case VerbGet:
		packet, err := snmp.Get(req.OIDs)
		return goSnmpResult(packet, err), nil
	case VerbGetNext:
		packet, err := snmp.GetNext(req.OIDs)
		return goSnmpResult(packet, err), nil
	case VerbGetBulk:
		reps := req.MaxRepetitions
		if reps <= 0 {
			reps = 10
		}
		packet, err := snmp.GetBulk(req.OIDs, 0, uint32(reps))
		return goSnmpResult(packet, err), nil
	case VerbWalk:
		var pdus []gosnmp.SnmpPDU
		var werr error
		if snmp.Version == gosnmp.Version1 {
			pdus, werr = snmp.WalkAll(req.OIDs[0])
		} else {
			pdus, werr = snmp.BulkWalkAll(req.OIDs[0])
		}
		if werr != nil {
			return goSnmpResult(nil, werr), nil
		}
		return Result{OK: true, Varbinds: goSnmpVarbinds(pdus)}, nil
	case VerbSet:
		pdus, perr := goSnmpPDUs(req.Varbinds)
		if perr != nil {
			return Result{ErrorKind: KindUsage, Error: perr.Error()}, nil
		}
		packet, err := snmp.Set(pdus)
		return goSnmpResult(packet, err), nil
	}
	return Result{ErrorKind: KindUsage, Error: "unknown verb " + string(req.Verb)}, nil
}

type goSnmpSecurity struct {
	flags     gosnmp.SnmpV3MsgFlags
	authProto gosnmp.SnmpV3AuthProtocol
	privProto gosnmp.SnmpV3PrivProtocol
}

func goSnmpLevel(req Request) (goSnmpSecurity, error) {
	level := req.Level
	if level == "" {
		switch {
		case req.Auth != "" && req.Priv != "":
			level = "authpriv"
		case req.Auth != "":
			level = "authnopriv"
		default:
			level = "noauthnopriv"
		}
	}
	out := goSnmpSecurity{authProto: gosnmp.SHA, privProto: gosnmp.AES}
	switch strings.ToLower(level) {
	case "noauthnopriv":
		out.flags = gosnmp.NoAuthNoPriv
		return out, nil
	case "authnopriv":
		out.flags = gosnmp.AuthNoPriv
	case "authpriv":
		out.flags = gosnmp.AuthPriv
	default:
		return out, fmt.Errorf("unknown level %q", level)
	}
	switch strings.ToLower(req.AuthProto) {
	case "", "sha":
		out.authProto = gosnmp.SHA
	case "md5":
		out.authProto = gosnmp.MD5
	case "sha224":
		out.authProto = gosnmp.SHA224
	case "sha256":
		out.authProto = gosnmp.SHA256
	case "sha384":
		out.authProto = gosnmp.SHA384
	case "sha512":
		out.authProto = gosnmp.SHA512
	default:
		return out, fmt.Errorf("unknown auth protocol %q", req.AuthProto)
	}
	switch strings.ToLower(req.PrivProto) {
	case "", "aes":
		out.privProto = gosnmp.AES
	case "des":
		out.privProto = gosnmp.DES
	case "aes192":
		out.privProto = gosnmp.AES192
	case "aes256":
		out.privProto = gosnmp.AES256
	default:
		return out, fmt.Errorf("unknown priv protocol %q", req.PrivProto)
	}
	return out, nil
}

func goSnmpPDUs(specs []string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	for _, spec := range specs {
		oid, rest, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("varbind %q: expected oid=TYPE:value", spec)
		}
		typeName, value, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("varbind %q: expected oid=TYPE:value", spec)
		}
		pdu := gosnmp.SnmpPDU{Name: oid}
		switch strings.ToLower(typeName) {
		case "string", "octetstring":
			pdu.Type = gosnmp.OctetString
			pdu.Value = []byte(value)
		case "int", "integer":
			n, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("varbind %q: %w", spec, err)
			}
			pdu.Type = gosnmp.Integer
			pdu.Value = int(n)
		case "oid":
			pdu.Type = gosnmp.ObjectIdentifier
			pdu.Value = value
		case "gauge", "unsigned":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("varbind %q: %w", spec, err)
			}
			pdu.Type = gosnmp.Gauge32
			pdu.Value = uint32(n)
		case "counter32":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("varbind %q: %w", spec, err)
			}
			pdu.Type = gosnmp.Counter32
			pdu.Value = uint32(n)
		case "counter64":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("varbind %q: %w", spec, err)
			}
			pdu.Type = gosnmp.Counter64
			pdu.Value = n
		case "timeticks":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("varbind %q: %w", spec, err)
			}
			pdu.Type = gosnmp.TimeTicks
			pdu.Value = uint32(n)
		default:
			return nil, fmt.Errorf("varbind %q: unknown type %q", spec, typeName)
		}
		out = append(out, pdu)
	}
	return out, nil
}

// goSnmpTrap builds the notification gosnmp expects. gosnmp does not add
// snmpTrapOID.0 itself (it would send a bare trap PDU), and SNMPv1 has no
// such varbind at all — it needs enterprise/generic/specific instead.
func goSnmpTrap(req Request) (gosnmp.SnmpTrap, error) {
	extras, err := goSnmpPDUs(req.Varbinds)
	if err != nil {
		return gosnmp.SnmpTrap{}, err
	}
	oid := ""
	if len(req.OIDs) > 0 {
		oid = req.OIDs[0]
	}
	if oid == "" {
		oid = "1.3.6.1.6.3.1.1.5.1"
	}
	trap := gosnmp.SnmpTrap{IsInform: req.Verb == VerbInform}
	if req.Version == "1" {
		enterprise, specific := splitEnterprise(oid)
		if req.Enterprise != "" {
			enterprise = req.Enterprise
		}
		if req.Specific != 0 {
			specific = req.Specific
		}
		generic := req.Generic
		if generic == 0 {
			generic = 6 // enterpriseSpecific
		}
		agent := req.AgentAddr
		if agent == "" {
			agent = "127.0.0.1"
		}
		trap.Enterprise = enterprise
		trap.GenericTrap = generic
		trap.SpecificTrap = specific
		trap.AgentAddress = agent
		trap.Timestamp = 100
		trap.Variables = extras
		return trap, nil
	}
	trap.Variables = append([]gosnmp.SnmpPDU{
		{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)},
		{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: oid},
	}, extras...)
	return trap, nil
}

// splitEnterprise turns "1.3.6.1.4.1.99.1" into ("1.3.6.1.4.1.99", 1), the
// RFC 2576 v1-trap shape.
func splitEnterprise(oid string) (string, int) {
	oid = strings.TrimPrefix(oid, ".")
	i := strings.LastIndex(oid, ".")
	if i < 0 {
		return oid, 0
	}
	n, err := strconv.Atoi(oid[i+1:])
	if err != nil {
		return oid, 0
	}
	return oid[:i], n
}

func goSnmpResult(packet *gosnmp.SnmpPacket, err error) Result {
	if err != nil {
		return Result{ErrorKind: classifyGoSnmp(err.Error()), Error: err.Error()}
	}
	if packet == nil {
		return Result{OK: true}
	}
	res := Result{OK: true}
	if packet.Error != gosnmp.NoError {
		res.OK = false
		res.ErrorKind = KindStatus
		res.Error = fmt.Sprintf("%s (index %d)", packet.Error, packet.ErrorIndex)
	}
	res.Varbinds = goSnmpVarbinds(packet.Variables)
	return res
}

func goSnmpVarbinds(pdus []gosnmp.SnmpPDU) []Varbind {
	out := make([]Varbind, 0, len(pdus))
	for _, pdu := range pdus {
		out = append(out, Varbind{
			OID:   strings.TrimPrefix(pdu.Name, "."),
			Type:  goSnmpTypeName(pdu.Type),
			Value: goSnmpValue(pdu),
		})
	}
	return out
}

func goSnmpTypeName(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.ObjectIdentifier:
		return "OID"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.IPAddress:
		return "IpAddress"
	case gosnmp.NoSuchObject:
		return "NoSuchObject"
	case gosnmp.NoSuchInstance:
		return "NoSuchInstance"
	case gosnmp.EndOfMibView:
		return "EndOfMibView"
	}
	return fmt.Sprintf("type(%d)", t)
}

func goSnmpValue(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case nil:
		return ""
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func classifyGoSnmp(text string) string {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "timeout") || strings.Contains(low, "no response"):
		return KindTimeout
	case strings.Contains(low, "unknown user"):
		return KindAuth
	case strings.Contains(low, "wrong digest") || strings.Contains(low, "authentication"):
		return KindAuth
	case strings.Contains(low, "decryption") || strings.Contains(low, "privacy"):
		return KindDecrypt
	case strings.Contains(low, "unsupported security"):
		return KindSecLevel
	case strings.Contains(low, "not in time window"):
		return KindTimeliness
	case strings.Contains(low, "unknown engine"):
		return KindNoEngine
	}
	return KindIndication
}

// notificationEngineID is a stable synthetic engine ID for a notifying peer:
// real agents have one fixed engine ID for their lifetime, and a fresh one
// per trap would look like an endless series of reboots to a replay cache.
func notificationEngineID(user string) string {
	sum := sha256.Sum256([]byte("conformance-notification:" + user))
	return "\x80\x00\x1f\x88\x80" + string(sum[:8])
}
