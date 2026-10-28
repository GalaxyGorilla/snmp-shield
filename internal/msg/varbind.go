package msg

import "fmt"

// Varbind is one decoded variable binding: a dotted OID (no leading dot)
// plus the raw value as tag + content. The caller interprets the value;
// this package deliberately does not know MIB types.
type Varbind struct {
	OID   string
	Type  byte
	Value []byte
}

// ParseVarbinds decodes the CONTENT of a varbind SEQUENCE — the slice
// PDUFields.Varbinds carries, with the outer SEQUENCE tag already removed.
//
// It is the single varbind decoder in the tree: the write policy uses it to
// learn which objects a SET touches, and the test fake agent uses it to
// implement real GETNEXT/GETBULK semantics. Keeping one implementation
// means a malformed varbind list cannot be "valid enough" for one caller
// and invalid for another.
//
// Every declared length is checked against the remaining buffer before it is
// sliced (the fuzz corpus pins that: a varbind whose length runs past the
// outer buffer is an error, never a panic).
func ParseVarbinds(content []byte) ([]Varbind, error) {
	var out []Varbind
	rest := content
	for len(rest) > 0 {
		tag, body, next, err := NextTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("varbind: %w", err)
		}
		rest = next
		if tag != 0x30 {
			return nil, fmt.Errorf("varbind: expected SEQUENCE, got tag 0x%02x", tag)
		}
		oidTag, oidBody, afterOID, err := NextTLV(body)
		if err != nil {
			return nil, fmt.Errorf("varbind oid: %w", err)
		}
		if oidTag != 0x06 {
			return nil, fmt.Errorf("varbind oid: expected OID, got tag 0x%02x", oidTag)
		}
		dotted, err := DecodeOID(oidBody)
		if err != nil {
			return nil, fmt.Errorf("varbind oid: %w", err)
		}
		valTag, valBody, afterVal, err := NextTLV(afterOID)
		if err != nil {
			return nil, fmt.Errorf("varbind value: %w", err)
		}
		if len(afterVal) != 0 {
			return nil, fmt.Errorf("varbind: %d trailing byte(s) inside SEQUENCE", len(afterVal))
		}
		out = append(out, Varbind{OID: dotted, Type: valTag, Value: valBody})
	}
	return out, nil
}

// BuildVarbinds assembles varbind-list CONTENT for BuildPDU (which wraps it
// in the SEQUENCE tag itself — passing an already-wrapped list double-wraps
// it and every real client rejects the message).
func BuildVarbinds(vbs []Varbind) []byte {
	var out []byte
	for _, vb := range vbs {
		encoded, err := EncodeOID(vb.OID)
		if err != nil {
			// Callers build varbinds from decoded or config-validated OIDs;
			// an unencodable one is a programming error, not a wire case.
			panic(fmt.Sprintf("msg.BuildVarbinds: %v", err))
		}
		body := AppendTLV(nil, 0x06, encoded)
		body = AppendTLV(body, vb.Type, vb.Value)
		out = AppendTLV(out, 0x30, body)
	}
	return out
}
