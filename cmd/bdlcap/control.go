package main

import (
	"io"
	"os"
	"sync"
)

// An extcap control packet has a 6-octet header followed by its payload. The
// header contains a sync byte, a 3-octet big-endian length, a control number,
// and a command.
const (
	controlSyncIndication byte = 'T'

	controlCmdStatusbar byte = 6
	controlCmdInfo      byte = 7
	controlCmdWarning   byte = 8
	controlCmdError     byte = 9
)

// control reports capture status to Wireshark. It only sends messages, so it
// does not use control numbers or accept commands.
//
// A nil *control discards messages when Wireshark provides no control channel.
type control struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// openControl opens the outbound channel and drains the unused inbound channel.
func openControl(in, out string) (*control, error) {
	var c *control
	if out != "" {
		w, err := os.OpenFile(out, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		c = &control{w: w}
	}
	if in != "" {
		r, err := os.OpenFile(in, os.O_RDONLY, 0)
		if err != nil {
			c.Close()
			return nil, err
		}
		go func() {
			defer r.Close()
			_, _ = io.Copy(io.Discard, r)
		}()
	}
	return c, nil
}

func (c *control) send(cmd byte, message string) {
	if c == nil || c.w == nil {
		return
	}
	payload := []byte(message)
	n := len(payload) + 2
	header := []byte{controlSyncIndication, byte(n >> 16), byte(n >> 8), byte(n), 0, cmd}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Ignore writes after Wireshark closes the pipe.
	_, _ = c.w.Write(append(header, payload...))
}

// Statusbar replaces the message shown in Wireshark's status bar.
func (c *control) Statusbar(s string) { c.send(controlCmdStatusbar, s) }

// Info, Warning, and Error show a dialog in Wireshark.
func (c *control) Info(s string)    { c.send(controlCmdInfo, s) }
func (c *control) Warning(s string) { c.send(controlCmdWarning, s) }
func (c *control) Error(s string)   { c.send(controlCmdError, s) }

func (c *control) Close() error {
	if c == nil || c.w == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.w.Close()
	c.w = nil
	return err
}
