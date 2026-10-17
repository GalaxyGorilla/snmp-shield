package tunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestFrameMarshalUnmarshal(t *testing.T) {
	f := &Frame{
		Type:      TypeREQ,
		Flags:     FlagInform,
		CorrID:    0xBEEF,
		FragIdx:   0,
		FragTotal: 1,
		Payload:   []byte("hello snmp"),
	}
	wire := f.Marshal()
	got, n, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n != len(wire) {
		t.Fatalf("consumed %d, want %d", n, len(wire))
	}
	if got.Type != f.Type || got.Flags != f.Flags || got.CorrID != f.CorrID ||
		got.FragIdx != f.FragIdx || got.FragTotal != f.FragTotal ||
		!bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFrameUnmarshalShort(t *testing.T) {
	if _, _, err := Unmarshal([]byte{0x01, 0x02}); err != ErrShort {
		t.Fatalf("want ErrShort, got %v", err)
	}
}

func TestFrameUnmarshalBadVersion(t *testing.T) {
	wire := (&Frame{Type: TypeREQ, Payload: []byte("x")}).Marshal()
	wire[0] = 99
	if _, _, err := Unmarshal(wire); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestFrameUnmarshalTruncatedPayload(t *testing.T) {
	wire := (&Frame{Type: TypeREQ, Payload: []byte("hello")}).Marshal()
	if _, _, err := Unmarshal(wire[:len(wire)-2]); err != ErrShort {
		t.Fatalf("want ErrShort, got %v", err)
	}
}

func TestFragmentSingle(t *testing.T) {
	payload := []byte("small payload")
	frames := Fragment(TypeRESP, 0, 7, payload, 1200)
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("payload mismatch")
	}
	if frames[0].FragTotal != 1 || frames[0].FragIdx != 0 {
		t.Fatalf("frag fields: %+v", frames[0])
	}
}

func TestFragmentAndReassemble(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5}, 5000) // > 1200 chunk
	frames := Fragment(TypeREQ, 0, 42, payload, 1200)
	if len(frames) < 4 {
		t.Fatalf("want >=4 fragments, got %d", len(frames))
	}
	// Verify each wire frame fits the chunk budget.
	for i, f := range frames {
		if len(f.Marshal()) > 1200 {
			t.Fatalf("frame %d exceeds chunk size: %d", i, len(f.Marshal()))
		}
		if f.FragTotal != uint16(len(frames)) {
			t.Fatalf("frame %d FragTotal=%d want %d", i, f.FragTotal, len(frames))
		}
		if f.FragIdx != uint16(i) {
			t.Fatalf("frame %d FragIdx=%d", i, f.FragIdx)
		}
	}
	c := NewChunker(65536)
	var out []byte
	now := time.Now()
	for _, f := range frames {
		wire := f.Marshal()
		parsed, _, err := Unmarshal(wire)
		if err != nil {
			t.Fatalf("unmarshal frag %d: %v", f.FragIdx, err)
		}
		got, err := c.Accept(parsed, now)
		if err != nil {
			t.Fatalf("accept frag %d: %v", f.FragIdx, err)
		}
		if got != nil {
			out = got
		}
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("reassembled %d bytes, want %d", len(out), len(payload))
	}
}

func TestFragmentOutOfOrder(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 3000)
	frames := Fragment(TypeREQ, 0, 9, payload, 1200)
	// Shuffle deterministically: swap 0 and 2.
	frames[0], frames[2] = frames[2], frames[0]
	c := NewChunker(65536)
	now := time.Now()
	var out []byte
	for _, f := range frames {
		got, err := c.Accept(f, now)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if got != nil {
			out = got
		}
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("out-of-order reassembly mismatch")
	}
}

func TestChunkerStaleGC(t *testing.T) {
	payload := bytes.Repeat([]byte{0x01}, 2000)
	frames := Fragment(TypeREQ, 0, 3, payload, 1200)
	c := NewChunker(65536)
	start := time.Now()
	// First fragment only: leaves a pending reassembly.
	if _, err := c.Accept(frames[0], start); err != nil {
		t.Fatal(err)
	}
	old := c.pending[3]
	if old == nil || len(c.pending) != 1 {
		t.Fatalf("pending=%d want 1", len(c.pending))
	}
	// After the deadline the stale entry is GC'd; the next fragment
	// starts a fresh reassembly for the same corrID.
	later := start.Add(11 * time.Second)
	if _, err := c.Accept(frames[1], later); err != nil {
		t.Fatal(err)
	}
	fresh := c.pending[3]
	if fresh == nil {
		t.Fatal("expected fresh pending entry after GC")
	}
	if fresh == old {
		t.Fatal("stale pending entry was not GC'd")
	}
	if !fresh.deadline.After(old.deadline) {
		t.Fatal("fresh entry should carry a later deadline")
	}
}

func TestChunkerBadSequence(t *testing.T) {
	payload := bytes.Repeat([]byte{0x02}, 2000)
	frames := Fragment(TypeREQ, 0, 5, payload, 1200)
	c := NewChunker(65536)
	now := time.Now()
	if _, err := c.Accept(frames[0], now); err != nil {
		t.Fatal(err)
	}
	// Same corrID, different fragTotal: ErrBadSequence is returned AND the
	// stale partial is dropped (resync) — the next matching fragment
	// starts a fresh reassembly.
	bad := &Frame{
		Type:      TypeREQ,
		CorrID:    5,
		FragIdx:   1,
		FragTotal: frames[0].FragTotal + 1,
		Payload:   []byte("x"),
	}
	if _, err := c.Accept(bad, now); err != ErrBadSequence {
		t.Fatalf("want ErrBadSequence, got %v", err)
	}
	if len(c.pending) != 0 {
		t.Fatal("stale partial should be dropped on fragTotal mismatch")
	}
	// Duplicate fragment: sequence error, partial stays for the live stream.
	if _, err := c.Accept(frames[0], now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Accept(frames[0], now); err != ErrBadSequence {
		t.Fatalf("dup: want ErrBadSequence, got %v", err)
	}
}

func TestFragmentOverflowGuard(t *testing.T) {
	// Huge payload with tiny chunk: FragTotal must stay in uint16 range.
	payload := bytes.Repeat([]byte{0x03}, 400*1024) // 400 KiB
	frames := Fragment(TypeREQ, 0, 1, payload, 1200)
	if len(frames) > 65535 {
		t.Fatalf("frag total overflow: %d", len(frames))
	}
	if len(frames) < 300 {
		t.Fatalf("expected many fragments, got %d", len(frames))
	}
}

func TestHeaderLayout(t *testing.T) {
	// Header field offsets are wire contract: verify explicitly.
	f := &Frame{Type: TypeNOTIF, Flags: 0xFF, CorrID: 0x0102, FragIdx: 0x0304, FragTotal: 0x0506, Payload: []byte{0xAA}}
	wire := f.Marshal()
	if wire[0] != Version || wire[1] != TypeNOTIF || wire[2] != 0xFF {
		t.Fatalf("header bytes 0-2: %v", wire[:3])
	}
	if binary.BigEndian.Uint16(wire[3:5]) != 0x0102 ||
		binary.BigEndian.Uint16(wire[5:7]) != 0x0304 ||
		binary.BigEndian.Uint16(wire[7:9]) != 0x0506 {
		t.Fatalf("header u16 fields: %v", wire[:9])
	}
	if binary.BigEndian.Uint32(wire[9:13]) != 1 {
		t.Fatalf("payload len: %v", wire[9:13])
	}
}
