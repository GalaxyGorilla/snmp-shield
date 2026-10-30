// des_test.go — DES privacy (RFC 3414 §8.1.1.1) at the primitive level.
//
// The end-to-end pin lives in internal/usm (a gosnmp DES client, both
// directions). What belongs here is the shape of the primitive itself: zero
// padding to the block boundary, the pre-IV derived from the key's second
// half XOR the salt, and — the part a peer controls — refusing malformed
// ciphertext instead of panicking on it.
package msg

import (
	"bytes"
	"testing"
)

// desKey is 16 bytes: the DES key followed by the pre-IV (RFC 3414 §8.1.1.1).
var desKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
}

func TestDESRoundTripPadsToBlockBoundary(t *testing.T) {
	salt := []byte{0, 0, 0, 0, 0, 0, 0, 7}

	for _, plain := range [][]byte{
		{},                  // empty plaintext still occupies one block
		{0x30},              // 1 byte
		[]byte("12345678"),  // exactly one block: no extra block
		[]byte("123456789"), // one byte over: padded to two blocks
		bytes.Repeat([]byte{0x30}, 100),
	} {
		tlv := EncryptDES(plain, desKey, salt)
		if tlv == nil {
			t.Fatalf("EncryptDES(%d bytes) returned nil", len(plain))
		}
		ct, err := berContent(tlv[1:])
		if err != nil {
			t.Fatalf("EncryptDES output is not an OCTET STRING TLV: %v", err)
		}
		if len(ct)%8 != 0 {
			t.Fatalf("ciphertext of %d bytes is not a DES block multiple", len(ct))
		}
		// padBlock always adds 1..8 zero bytes, i.e. a plaintext that is
		// already a multiple of 8 gets a full block of padding. RFC 3414
		// §8.1.1.1 only requires padding when the plaintext is not a
		// multiple; gosnmp does the same as us (its `pad` is
		// `blocksize - len%blocksize`), and it is immaterial on the wire
		// because the receiver parses the scopedPDU by its BER length and
		// ignores what follows.
		if want := (len(plain)/8 + 1) * 8; len(ct) != want {
			t.Fatalf("ciphertext = %d bytes, want %d (zero padding to a block boundary)", len(ct), want)
		}

		got, err := DecryptDES(ct, desKey, salt)
		if err != nil {
			t.Fatalf("DecryptDES: %v", err)
		}
		if len(got) != len(ct) {
			t.Fatalf("decrypted %d bytes, want %d (padding is the caller's to strip)", len(got), len(ct))
		}
		if !bytes.HasPrefix(got, plain) {
			t.Fatalf("decrypted prefix = %x, want %x", got[:len(plain)], plain)
		}
		if !bytes.Equal(got[len(plain):], make([]byte, len(got)-len(plain))) {
			t.Fatalf("padding is not zeros: %x", got[len(plain):])
		}
	}
}

// TestDESIVIsKeyHalfXorSalt pins the pre-IV rule. A wrong IV still
// round-trips against itself, so a self-consistency test cannot see it; what
// it can see is that the IV really depends on both halves: same plaintext and
// key, different salt => different ciphertext, and decrypting with the wrong
// salt must not give the plaintext back.
func TestDESIVIsKeyHalfXorSalt(t *testing.T) {
	plain := []byte("scopedPDU bytes")

	a := EncryptDES(plain, desKey, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	b := EncryptDES(plain, desKey, []byte{0, 0, 0, 0, 0, 0, 0, 2})
	if bytes.Equal(a, b) {
		t.Fatal("two different salts produced the same ciphertext: the salt is not in the IV")
	}

	// The key's SECOND half is the pre-IV; changing it must change the
	// ciphertext too (a DES key that only used key[:8] would pass the salt
	// check above).
	other := append([]byte(nil), desKey...)
	other[15] ^= 0xff
	c := EncryptDES(plain, other, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	if bytes.Equal(a, c) {
		t.Fatal("changing the pre-IV half of the key did not change the ciphertext")
	}

	ct, err := berContent(a[1:])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptDES(ct, desKey, []byte{0, 0, 0, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("DecryptDES with the wrong salt must not error, it must produce garbage: %v", err)
	} else if bytes.HasPrefix(got, plain) {
		t.Fatal("decrypting with the wrong salt recovered the plaintext")
	}
}

// TestDESRejectsMalformedInput: ciphertext and keys come from the wire (or
// from a misconfigured profile), so neither may panic. A non-block-multiple
// ciphertext is what a truncated or hostile message looks like.
func TestDESRejectsMalformedInput(t *testing.T) {
	salt := make([]byte, 8)

	// An empty ciphertext is accepted as an empty plaintext (0 is a block
	// multiple, and gosnmp accepts it too); it cannot be a scopedPDU, so the
	// BER parse upstream is what rejects it. What must never happen is a
	// panic or a partially filled buffer.
	if got, err := DecryptDES(nil, desKey, salt); err != nil || len(got) != 0 {
		t.Fatalf("DecryptDES(nil) = %x, %v; want empty, nil", got, err)
	}
	for _, ct := range [][]byte{
		{0x01},
		bytes.Repeat([]byte{0xaa}, 7),
		bytes.Repeat([]byte{0xaa}, 9),
	} {
		if _, err := DecryptDES(ct, desKey, salt); err == nil {
			t.Fatalf("DecryptDES accepted %d bytes of ciphertext", len(ct))
		}
	}

	// Short keys: slicing key[:8] would panic, so the guard is the property.
	for _, key := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{1}, 15)} {
		if out := EncryptDES([]byte("x"), key, salt); out != nil {
			t.Fatalf("EncryptDES accepted a %d-byte key", len(key))
		}
		if _, err := DecryptDES(bytes.Repeat([]byte{0xaa}, 8), key, salt); err == nil {
			t.Fatalf("DecryptDES accepted a %d-byte key", len(key))
		}
	}
	if _, err := DecryptDES(bytes.Repeat([]byte{0xaa}, 8), desKey, []byte{1, 2, 3}); err == nil {
		t.Fatal("DecryptDES accepted a 3-byte salt")
	}
	if out := EncryptDES([]byte("x"), desKey, []byte{1, 2, 3}); out != nil {
		t.Fatal("EncryptDES accepted a 3-byte salt")
	}
}
