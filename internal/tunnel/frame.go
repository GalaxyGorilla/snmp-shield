// Package tunnel implements the secured-segment transport: a framed,
// multiplexed channel over DTLS/UDP (primary) or TLS/TCP (alternative).
package tunnel

import (
	"encoding/binary"
	"errors"
	"time"
)

// Frame wire format (big-endian):
//
//	uint8  version (1)
//	uint8  type
//	uint8  flags
//	uint16 corrID
//	uint16 fragIdx
//	uint16 fragTotal
//	uint32 len
//	bytes  payload[len]
const (
	frameHeaderLen = 13
	Version        = 1
	maxPayload     = 65535
)

// Frame types.
const (
	TypeREQ    uint8 = 1 // clear SNMP request datagram, manager->agent direction
	TypeRESP   uint8 = 2 // clear SNMP response datagram, agent->manager direction
	TypeNOTIF  uint8 = 3 // trap/inform datagram, agent-side -> manager-side
	TypePING   uint8 = 4
	TypePONG   uint8 = 5
	TypeGOAWAY uint8 = 6
)

// Frame flags.
const (
	FlagInform uint8 = 0x01 // NOTIF carries an inform (response expected)
)

// Errors returned by frame parsing and reassembly.
var (
	ErrShort       = errors.New("tunnel: frame too short")
	ErrBadVersion  = errors.New("tunnel: unsupported frame version")
	ErrTooLarge    = errors.New("tunnel: frame exceeds limit")
	ErrBadSequence = errors.New("tunnel: frame sequence error")
)

// Frame is one multiplexed application datagram on the secured segment.
type Frame struct {
	Type      uint8
	Flags     uint8
	CorrID    uint16
	FragIdx   uint16
	FragTotal uint16
	Payload   []byte
}

// Marshal returns the wire encoding of f.
func (f *Frame) Marshal() []byte {
	out := make([]byte, frameHeaderLen+len(f.Payload))
	out[0] = Version
	out[1] = f.Type
	out[2] = f.Flags
	binary.BigEndian.PutUint16(out[3:5], f.CorrID)
	binary.BigEndian.PutUint16(out[5:7], f.FragIdx)
	binary.BigEndian.PutUint16(out[7:9], f.FragTotal)
	binary.BigEndian.PutUint32(out[9:13], uint32(len(f.Payload)))
	copy(out[frameHeaderLen:], f.Payload)
	return out
}

// Unmarshal parses a complete frame from buf. It returns the frame and
// the number of bytes consumed.
func Unmarshal(buf []byte) (*Frame, int, error) {
	if len(buf) < frameHeaderLen {
		return nil, 0, ErrShort
	}
	if buf[0] != Version {
		return nil, 0, ErrBadVersion
	}
	f := &Frame{
		Type:      buf[1],
		Flags:     buf[2],
		CorrID:    binary.BigEndian.Uint16(buf[3:5]),
		FragIdx:   binary.BigEndian.Uint16(buf[5:7]),
		FragTotal: binary.BigEndian.Uint16(buf[7:9]),
	}
	plen := binary.BigEndian.Uint32(buf[9:13])
	if plen > maxPayload {
		return nil, 0, ErrTooLarge
	}
	if int(plen) > len(buf)-frameHeaderLen {
		return nil, 0, ErrShort
	}
	f.Payload = buf[frameHeaderLen : frameHeaderLen+int(plen)]
	return f, frameHeaderLen + int(plen), nil
}

// UnmarshalHeader parses just the frame header (13 bytes), without the
// payload-length satisfaction check. Use when the payload has not been
// read yet (e.g. the session read loop).
func UnmarshalHeader(hdr []byte) (*Frame, error) {
	if len(hdr) < frameHeaderLen {
		return nil, ErrShort
	}
	if hdr[0] != Version {
		return nil, ErrBadVersion
	}
	return &Frame{
		Type:      hdr[1],
		Flags:     hdr[2],
		CorrID:    binary.BigEndian.Uint16(hdr[3:5]),
		FragIdx:   binary.BigEndian.Uint16(hdr[5:7]),
		FragTotal: binary.BigEndian.Uint16(hdr[7:9]),
	}, nil
}

// part tracks one in-progress reassembly.
type part struct {
	fragTotal uint16
	got       map[uint16][]byte
	deadline  time.Time
}

// Chunker reassembles fragmented frames by corrID.
type Chunker struct {
	max     int
	pending map[uint16]*part
	lastGC  time.Time
}

// NewChunker creates a Chunker accepting reassembled payloads up to max
// bytes.
func NewChunker(max int) *Chunker {
	return &Chunker{
		max:     max,
		pending: make(map[uint16]*part),
		lastGC:  time.Now(),
	}
}

// Accept takes one wire frame, returning the complete reassembled
// payload, or (nil, nil) when more fragments are needed. CorrIDs are
// reused over time, so Accept also runs opportunistic GC of stale
// partial reassemblies.
func (c *Chunker) Accept(f *Frame, now time.Time) ([]byte, error) {
	c.gc(now)
	if f.FragTotal <= 1 {
		if len(f.Payload) > c.max {
			return nil, ErrTooLarge
		}
		return append([]byte(nil), f.Payload...), nil
	}
	if f.FragIdx >= f.FragTotal {
		return nil, ErrBadSequence
	}
	p := c.pending[f.CorrID]
	if p == nil {
		p = &part{
			fragTotal: f.FragTotal,
			got:       make(map[uint16][]byte),
			deadline:  now.Add(10 * time.Second),
		}
		c.pending[f.CorrID] = p
	}
	if p.fragTotal != f.FragTotal {
		delete(c.pending, f.CorrID)
		return nil, ErrBadSequence
	}
	if _, dup := p.got[f.FragIdx]; dup {
		return nil, ErrBadSequence
	}
	p.got[f.FragIdx] = append([]byte(nil), f.Payload...)
	if uint16(len(p.got)) < p.fragTotal {
		return nil, nil
	}
	out := make([]byte, 0, c.max)
	for i := uint16(0); i < p.fragTotal; i++ {
		out = append(out, p.got[i]...)
	}
	delete(c.pending, f.CorrID)
	return out, nil
}

// gc drops stale partial reassemblies, at most once per second.
func (c *Chunker) gc(now time.Time) {
	if now.Sub(c.lastGC) < time.Second {
		return
	}
	c.lastGC = now
	for id, p := range c.pending {
		if now.After(p.deadline) {
			delete(c.pending, id)
		}
	}
}

// Fragment splits payload into wire frames of at most chunk bytes each
// (including the 13-byte header), all sharing corrID. It returns at
// least one frame.
func Fragment(typ, flags uint8, corrID uint16, payload []byte, chunk int) []*Frame {
	if chunk < frameHeaderLen+1 {
		chunk = frameHeaderLen + 1
	}
	maxData := chunk - frameHeaderLen
	n := (len(payload) + maxData - 1) / maxData
	if n == 0 {
		n = 1
	}
	if n > maxPayload {
		n = maxPayload // payload beyond ~128 MiB is not supported
	}
	frames := make([]*Frame, 0, n)
	for i := 0; i < n; i++ {
		lo := i * maxData
		hi := lo + maxData
		if hi > len(payload) {
			hi = len(payload)
		}
		frames = append(frames, &Frame{
			Type:      typ,
			Flags:     flags,
			CorrID:    corrID,
			FragIdx:   uint16(i),
			FragTotal: uint16(n),
			Payload:   payload[lo:hi],
		})
	}
	return frames
}
