package main

import (
	"bytes"
	"testing"

	"github.com/natebenes/bdlcap/internal/wire"
)

// TestSampleMessagesRoundTrip verifies that the sample capture is well formed.
func TestSampleMessagesRoundTrip(t *testing.T) {
	msgs := sampleMessages()
	if len(msgs) == 0 {
		t.Fatal("sampleMessages returned nothing")
	}
	for i, m := range msgs {
		raw, err := m.Encode()
		if err != nil {
			t.Fatalf("sample %d (%v): Encode: %v", i, m.Function, err)
		}
		back, err := wire.Decode(raw)
		if err != nil {
			t.Fatalf("sample %d (%v): Decode: %v", i, m.Function, err)
		}
		again, err := back.Encode()
		if err != nil {
			t.Fatalf("sample %d (%v): re-encode: %v", i, m.Function, err)
		}
		if !bytes.Equal(raw, again) {
			t.Errorf("sample %d (%v) does not round trip:\n in %x\nout %x", i, m.Function, raw, again)
		}
		// Capture files contain only endpoint-to-tool messages.
		if !m.Function.FromEndpoint() {
			t.Errorf("sample %d is %v, which a diagnostic endpoint never sends", i, m.Function)
		}
	}
}

// TestSampleCoversEveryMessage verifies all endpoint messages and dissector
// mappings used by the sample capture.
func TestSampleCoversEveryMessage(t *testing.T) {
	functions := map[wire.Function]bool{}
	dissectors := map[string]bool{}
	truncated := false
	nak := false
	for _, m := range sampleMessages() {
		functions[m.Function] = true
		if m.Function != wire.FnFrame {
			if m.Err != nil {
				nak = true
			}
			continue
		}
		dissectors[m.NetworkType.Dissector()] = true
		if m.OriginalLength > uint32(len(m.FrameData)) {
			truncated = true
		}
	}
	for _, want := range []wire.Function{
		wire.FnAcknowledge, wire.FnFrame, wire.FnDrop, wire.FnConnect, wire.FnDisconnect,
	} {
		if !functions[want] {
			t.Errorf("the sample has no %v message", want)
		}
	}
	for _, want := range []string{"bscvlc", "bvlc", "mstp", "bacnet"} {
		if !dissectors[want] {
			t.Errorf("the sample has no frame that dissects as %s", want)
		}
	}
	if !truncated {
		t.Error("the sample has no truncated frame")
	}
	if !nak {
		t.Error("the sample has no message carrying an error")
	}
}

// TestMSTPFrameCRCs verifies the sample MS/TP CRCs defined by Clause 9.5.
func TestMSTPFrameCRCs(t *testing.T) {
	data := npdu()
	f := mstpFrame(0x06, 0x0C, 0x05, data)

	if f[0] != 0x55 || f[1] != 0xFF {
		t.Errorf("preamble = %x, want 55ff", f[:2])
	}
	// A receiver recomputes the header CRC over the header and the received
	// CRC octet; the result is a fixed residue of 0x55.
	crc := uint16(0xFF)
	for _, b := range f[2:8] {
		c := crc ^ uint16(b)
		c = c ^ (c << 1) ^ (c << 2) ^ (c << 3) ^ (c << 4) ^ (c << 5) ^ (c << 6) ^ (c << 7)
		crc = (c & 0xFE) ^ ((c >> 8) & 1)
	}
	if byte(crc) != 0x55 {
		t.Errorf("header CRC residue = %#02x, want 0x55", byte(crc))
	}
	if got, want := int(f[5])<<8|int(f[6]), len(data); got != want {
		t.Errorf("length field = %d, want %d", got, want)
	}
	if got, want := len(f), 8+len(data)+2; got != want {
		t.Errorf("frame length = %d, want %d", got, want)
	}
}
