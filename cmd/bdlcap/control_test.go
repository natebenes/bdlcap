package main

import (
	"bytes"
	"testing"
)

// nopWriteCloser captures control-channel output without closing the buffer.
type nopWriteCloser struct{ bytes.Buffer }

func (n *nopWriteCloser) Close() error { return nil }

// TestControlFraming verifies the extcap control packet layout.
func TestControlFraming(t *testing.T) {
	var buf nopWriteCloser
	c := &control{w: &buf}
	c.Warning("dropped 42 frames")

	got := buf.Bytes()
	if got[0] != controlSyncIndication {
		t.Errorf("sync indication = %#02x, want %#02x", got[0], controlSyncIndication)
	}
	payload := "dropped 42 frames"
	wantLen := len(payload) + 2
	if n := int(got[1])<<16 | int(got[2])<<8 | int(got[3]); n != wantLen {
		t.Errorf("length = %d, want %d", n, wantLen)
	}
	if got[5] != controlCmdWarning {
		t.Errorf("command = %d, want %d", got[5], controlCmdWarning)
	}
	if string(got[6:]) != payload {
		t.Errorf("payload = %q, want %q", got[6:], payload)
	}
	if len(got) != 6+len(payload) {
		t.Errorf("wrote %d octets, want %d", len(got), 6+len(payload))
	}
}

// TestControlNilIsSilent verifies operation without a control channel.
func TestControlNilIsSilent(t *testing.T) {
	var c *control
	c.Statusbar("connected")
	c.Info("installed")
	c.Warning("dropped")
	c.Error("refused")
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
