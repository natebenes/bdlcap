package pcapng

import (
	"bytes"
	"testing"
	"time"
)

// block contains one parsed pcapng block.
type block struct {
	typ  uint32
	body []byte // between the leading and trailing total-length fields
}

// parseBlocks parses a pcapng stream and validates block lengths and alignment.
func parseBlocks(t *testing.T, b []byte) []block {
	t.Helper()
	var blocks []block
	for i := 0; i < len(b); {
		if i+12 > len(b) {
			t.Fatalf("block at offset %d is shorter than the minimum 12 octets", i)
		}
		typ := u32(b[i:])
		total := int(u32(b[i+4:]))
		if total%4 != 0 {
			t.Fatalf("block at offset %d has total length %d, not a multiple of 4", i, total)
		}
		if total < 12 || i+total > len(b) {
			t.Fatalf("block at offset %d claims %d octets, %d remain", i, total, len(b)-i)
		}
		if trailing := u32(b[i+total-4:]); trailing != uint32(total) {
			t.Fatalf("block at offset %d: trailing length %d, leading %d", i, trailing, total)
		}
		blocks = append(blocks, block{typ: typ, body: b[i+8 : i+total-4]})
		i += total
	}
	return blocks
}

func u16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func TestWriterStructure(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeUser15, "bdlcap test", "bdc", "BACnet Diagnostic Connection")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ts := time.Unix(1700000000, 123456000).UTC()
	payload := []byte{0x11, 0x00, 0x01}
	if err := w.WritePacket(ts, len(payload), payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	blocks := parseBlocks(t, buf.Bytes())
	if len(blocks) != 3 {
		t.Fatalf("got %d blocks, want section header, interface description, and one packet", len(blocks))
	}
	if blocks[0].typ != blockSectionHeader {
		t.Errorf("block 0 type = %#x, want section header", blocks[0].typ)
	}
	if magic := u32(blocks[0].body); magic != byteOrderMagic {
		t.Errorf("byte order magic = %#x, want %#x", magic, byteOrderMagic)
	}
	if blocks[1].typ != blockInterfaceDesc {
		t.Errorf("block 1 type = %#x, want interface description", blocks[1].typ)
	}
	if lt := u16(blocks[1].body); lt != LinkTypeUser15 {
		t.Errorf("link type = %d, want %d", lt, LinkTypeUser15)
	}
	if blocks[2].typ != blockEnhancedPacket {
		t.Errorf("block 2 type = %#x, want enhanced packet", blocks[2].typ)
	}

	epb := blocks[2].body
	if id := u32(epb); id != 0 {
		t.Errorf("interface id = %d, want 0", id)
	}
	gotMicros := uint64(u32(epb[4:]))<<32 | uint64(u32(epb[8:]))
	if want := uint64(ts.UnixMicro()); gotMicros != want {
		t.Errorf("timestamp = %d, want %d", gotMicros, want)
	}
	if got, want := u32(epb[12:]), uint32(len(payload)); got != want {
		t.Errorf("captured length = %d, want %d", got, want)
	}
	if got, want := u32(epb[16:]), uint32(len(payload)); got != want {
		t.Errorf("original length = %d, want %d", got, want)
	}
	if got := epb[20 : 20+len(payload)]; !bytes.Equal(got, payload) {
		t.Errorf("packet data = %x, want %x", got, payload)
	}
}

// TestWriterTruncation verifies the pcapng lengths of an LPDU truncated by the
// endpoint.
func TestWriterTruncation(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeUser15, "bdlcap test", "bdc", "")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	payload := []byte{1, 2, 3, 4, 5}
	if err := w.WritePacket(time.Unix(0, 0), 500, payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	blocks := parseBlocks(t, buf.Bytes())
	epb := blocks[len(blocks)-1].body
	if got, want := u32(epb[12:]), uint32(5); got != want {
		t.Errorf("captured length = %d, want %d", got, want)
	}
	if got, want := u32(epb[16:]), uint32(500); got != want {
		t.Errorf("original length = %d, want %d", got, want)
	}
}

func TestWriterRejectsShortOriginalLength(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeUser15, "bdlcap test", "bdc", "")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WritePacket(time.Unix(0, 0), 2, []byte{1, 2, 3}); err == nil {
		t.Fatal("WritePacket succeeded with an original length below the captured length")
	}
}

// TestWriterPadding verifies 32-bit alignment for every packet-length remainder.
func TestWriterPadding(t *testing.T) {
	for n := 1; n <= 8; n++ {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, LinkTypeUser0, "bdlcap test", "bdc", "")
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		data := bytes.Repeat([]byte{0xAB}, n)
		for range 3 {
			if err := w.WritePacket(time.Unix(0, 0), n, data); err != nil {
				t.Fatalf("WritePacket: %v", err)
			}
		}
		if got := len(parseBlocks(t, buf.Bytes())); got != 5 {
			t.Errorf("payload of %d octets: got %d blocks, want 5", n, got)
		}
	}
}
