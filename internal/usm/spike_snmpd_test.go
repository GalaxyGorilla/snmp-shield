// spike_snmpd_test.go — RISK-FIRST SPIKE for the manager-gateway mode:
// our v3 REQUESTS (discovery + authPriv GET) have never faced a real
// SNMP agent as the verifying peer. This spike points the exact msg
// building blocks used by translate_manager.go (ensureEngine /
// buildV3Request) at the real local snmpd (127.0.0.1:161) configured
// with a v3 authPriv user, and asserts:
//
//  1. RFC 3414 discovery: Reportable|NoAuthNoPriv empty GET -> the
//     agent's Report carries its engineID/boots/time.
//  2. An authPriv GET for sysDescr.0 signed+encrypted with the
//     discovered engine state is ACCEPTED and answered with a verifiable
//     GetResponse (digest verify + AES decrypt against the wire state).
//
// Build constraint keeps it out of normal runs (run with
// -tags snmpd_spike). Requires snmpd with:
//
//	createUser authPrivUser SHA "authpass123" AES "privpass123"
//	rouser authPrivUser authpriv -V systemonly

//go:build snmpd_spike

package usm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
)

const (
	spikeAddr     = "127.0.0.1:1161"
	spikeUser     = "authPrivUser"
	spikeAuthPass = "authpass123"
	spikePrivPass = "privpass123"
)

// spikeEngine is the discovered remote engine state (minimal local
// mirror of remoteEngine for the spike).
type spikeEngine struct {
	id    []byte
	boots uint32
	time  uint32
}

// spikeUDP sends one datagram and waits for one response on a fresh
// ephemeral socket (per-message reply address — the spike is one-shot).
func spikeUDP(t *testing.T, out []byte, wait time.Duration) []byte {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", spikeAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no local UDP: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(wait)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo(out, raddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no response from snmpd (is it running with createUser authPrivUser SHA %q AES %q?): %v",
				spikeAuthPass, spikePrivPass, err)
		}
		dg := append([]byte(nil), buf[:n]...)
		// skip stray datagrams: we only accept v3 back
		if info, perr := msg.Peek(dg); perr == nil && info.Version == msg.Version3 {
			return dg
		}
	}
}

// spikeDiscovery performs RFC 3414 discovery against the real snmpd:
// a Reportable NoAuthNoPriv empty GET; the Report carries the engineID.
func spikeDiscovery(t *testing.T) *spikeEngine {
	t.Helper()

	pdu := msg.BuildPDU(msg.PDUGetRequest, 1, 0, 0, []byte{0}) // empty varbind-list content
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      100,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		t.Fatal(err)
	}

	dg := spikeUDP(t, out, 3*time.Second)
	m, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("discovery response unparseable: %v", err)
	}
	if len(m.USM.EngineID) == 0 {
		t.Fatalf("discovery Report carries no engineID (USM=%+v)", m.USM)
	}
	eng := &spikeEngine{id: m.USM.EngineID, boots: m.USM.Boots, time: m.USM.Time}
	t.Logf("DISCOVERY OK: engineID=%x boots=%d time=%d", eng.id, eng.boots, eng.time)
	return eng
}

// spikeAuthPrivGet sends a real authPriv GET for sysDescr.0 signed and
// encrypted with the discovered engine state, verifies the response
// digest, decrypts it, and returns the PDU type + varbind count.
func spikeAuthPrivGet(t *testing.T, eng *spikeEngine) {
	t.Helper()

	prof := Profile{
		Name:           spikeUser,
		AuthProtocol:   AuthSHA,
		AuthPassphrase: spikeAuthPass,
		PrivProtocol:   PrivAES,
		PrivPassphrase: spikePrivPass,
	}
	profC, err := NewProfiles([]Profile{prof}, eng.id)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := profC.Lookup(spikeUser)
	if !ok {
		t.Fatal("user not compiled")
	}

	// GET sysDescr.0: BuildPDU's varbinds argument is the RAW
	// varbind-list content (BuildPDU wraps it in the 0x30 SEQUENCE
	// itself) — passing a pre-wrapped list double-wraps it (the exact
	// gotcha AGENTS.md documents from the v1-trap translation bug).
	oid := mustSpikeOID(t, ".1.3.6.1.2.1.1.1.0")
	// varbind = SEQUENCE(0x30){ OID(0x06), NULL(0x05 00) }: content is
	// the OID TLV (2+len bytes) + 2 NULL bytes.
	vb := append([]byte{0x30, byte(len(oid) + 2)}, oid...)
	vb = append(vb, 0x05, 0x00)
	pdu := msg.BuildPDU(msg.PDUGetRequest, 42, 0, 0, vb)
	scoped := msg.BuildScoped(eng.id, []byte{}, pdu)

	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable)
	privParams := make([]byte, 8)
	binary.BigEndian.PutUint32(privParams[4:], 1) // salt counter low word

	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      101,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   eng.id,
		Boots:      eng.boots,
		Time:       eng.time,
		UserName:   spikeUser,
		AuthParams: make([]byte, c.p.AuthProtocol.MacLength()),
		PrivParams: privParams,
	}, scoped, func(plain []byte) ([]byte, error) {
		return encryptScoped(c.p.PrivProtocol, c.privKey, eng.boots, eng.time, privParams, plain)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := signV3(out, c.p.AuthProtocol, c.authKey); err != nil {
		t.Fatal(err)
	}

	dg := spikeUDP(t, out, 3*time.Second)
	m2, err := msg.ParseV3(dg)
	if err != nil {
		t.Fatalf("response unparseable: %v", err)
	}

	// verify + decrypt the response with our localized keys (the agent
	// signed/encrypted with the same user credentials)
	_, plain, err := unwrapV3(profC, m2, dg)
	if err != nil {
		t.Fatalf("response REJECTED by our own verification (agent's reply not verifiable?): %v", err)
	}
	pduType, fields, err := msg.ParsePDU(plain)
	if err != nil {
		t.Fatalf("decrypted PDU unparseable: %v", err)
	}
	t.Logf("AUTHPRIV GET OK: engine accepted our signed+encrypted request; response PDU type=%#x errStatus=%d varbinds=%d boots=%d time=%d",
		pduType, fields.ErrStatus, len(fields.Varbinds), m2.USM.Boots, m2.USM.Time)
	if fields.ErrStatus != 0 {
		t.Fatalf("agent returned error status %d (index %d)", fields.ErrStatus, fields.ErrIndex)
	}
	if len(fields.Varbinds) == 0 {
		t.Fatal("GetResponse carries no varbinds")
	}
}

func TestSpikeRealSnmpdAuthPriv(t *testing.T) {
	eng := spikeDiscovery(t)
	spikeAuthPrivGet(t, eng)
}

// mustSpikeOID encodes a dotted OID string into BER TLV (tag 0x06).
func mustSpikeOID(t *testing.T, dotted string) []byte {
	t.Helper()
	out, err := encodeSpikeOID(dotted)
	if err != nil {
		t.Fatalf("encode OID %s: %v", dotted, err)
	}
	return out
}

func encodeSpikeOID(dotted string) ([]byte, error) {
	var arcs []uint32
	var cur uint32
	has := false
	for i := 0; i <= len(dotted); i++ {
		if i == len(dotted) || dotted[i] == '.' {
			if has {
				arcs = append(arcs, cur)
			}
			cur, has = 0, false
			continue
		}
		if dotted[i] < '0' || dotted[i] > '9' {
			return nil, errors.New("bad OID char")
		}
		cur = cur*10 + uint32(dotted[i]-'0')
		has = true
	}
	if len(arcs) < 2 {
		return nil, fmt.Errorf("OID %s too short", dotted)
	}
	// first arc = 40*a+b
	body := []byte{byte(arcs[0]*40 + arcs[1])}
	body = appendSpikeBase128(body, arcs[2:]...)
	out := append([]byte{0x06, byte(len(body))}, body...)
	return out, nil
}

func appendSpikeBase128(dst []byte, arcs ...uint32) []byte {
	for _, a := range arcs {
		if a == 0 {
			dst = append(dst, 0)
			continue
		}
		var tmp [5]byte
		n := 0
		for a > 0 {
			tmp[n] = byte(a & 0x7f)
			a >>= 7
			n++
		}
		for i := n - 1; i >= 0; i-- {
			b := tmp[i]
			if i != 0 {
				b |= 0x80
			}
			dst = append(dst, b)
		}
	}
	return dst
}
