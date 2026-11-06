package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/natebenes/bdlcap/internal/pcapng"
	"github.com/natebenes/bdlcap/internal/wire"
)

// cmdSample writes one of each endpoint message for testing the Lua dissector.
func cmdSample(args []string) error {
	fs := flag.NewFlagSet("sample", flag.ExitOnError)
	out := fs.String("out", "bdc-sample.pcapng", "file to write")
	linkType := fs.Uint("linktype", uint(pcapng.LinkTypeUser15), "pcapng link type to write")
	_ = fs.Parse(args) // ExitOnError: Parse exits rather than returning an error.

	lt, err := parseLinkType(*linkType)
	if err != nil {
		return err
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()

	w, err := pcapng.NewWriter(f, lt, "bdlcap "+version, ifaceName,
		"BACnet Diagnostic Connection sample")
	if err != nil {
		return err
	}

	start := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	for i, m := range sampleMessages() {
		raw, err := m.Encode()
		if err != nil {
			return fmt.Errorf("encoding sample %d (%v): %w", i, m.Function, err)
		}
		originalLen := len(raw)
		if m.Function == wire.FnFrame {
			originalLen += int(m.OriginalLength) - len(m.FrameData)
		}
		if err := w.WritePacket(start.Add(time.Duration(i)*10*time.Millisecond), originalLen, raw); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %s\n", *out)
	return nil
}

func sampleMessages() []*wire.Message {
	// BACnet/SC Encapsulated-NPDU carrying a ReadProperty request.
	bvlcSC := append([]byte{0x01, 0x00, 0x00, 0x01}, npdu()...)
	// A BACnet/IP BVLC message: Original-Unicast-NPDU.
	bvlcIP := append([]byte{0x81, 0x0A, 0x00, byte(4 + len(npdu()))}, npdu()...)

	peer := &wire.Peer{
		HostKind: wire.HostIP,
		HostIP:   []byte{10, 0, 0, 5},
		Port:     47808,
		SAN:      "bacnet://1234",
		Fingerprint: []byte{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		},
	}
	mstp := mstpFrame(0x06, 0x0C, 0x05, npdu()) // Data Expecting Reply

	var ts uint64 = 1_000_000
	next := func() uint64 { ts += 25_000; return ts }

	return []*wire.Message{
		// The endpoint accepts the capture request.
		{Function: wire.FnAcknowledge},
		// A BACnet/SC frame received on port 3.
		frame(next(), 3, wire.NetworkSecureConnect, wire.PositionReceive,
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, bvlcSC),
		// A BACnet/IP frame transmitted from port 4; the mac addresses are
		// the six-octet IP and port of each peer.
		frame(next(), 4, wire.NetworkIPv4, wire.PositionTransmit,
			[]byte{192, 168, 1, 20, 0xBA, 0xC0}, []byte{192, 168, 1, 10, 0xBA, 0xC0}, bvlcIP),
		// An MS/TP frame on port 7, whose mac addresses are one octet.
		frame(next(), 7, wire.NetworkMSTP, wire.PositionReceive,
			[]byte{0x0C}, []byte{0x05}, mstp),
		// An Ethernet port carries a bare NPDU (Table YY-5).
		frame(next(), 8, wire.NetworkEthernet, wire.PositionReceive,
			[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, npdu()),
		// A frame the endpoint had to shorten to fit the WebSocket message.
		truncated(next(), 3, wire.NetworkSecureConnect, bvlcSC, 1500),
		// An accepted connection followed by a device-initiated disconnect.
		{Function: wire.FnConnect, Timestamp: next(), NetworkPort: 3,
			NetworkType: wire.NetworkSecureConnect, Peer: peer},
		{Function: wire.FnDisconnect, Timestamp: next(), NetworkPort: 3,
			NetworkType: wire.NetworkSecureConnect, Peer: peer,
			Err: &wire.Error{Class: wire.ClassCommunication, Code: wire.CodeOther}},
		// Frames dropped because the tool fell behind.
		{Function: wire.FnDrop, DropCount: 42},
		// A request rejected because the network port does not exist (YY.3.1).
		{Function: wire.FnAcknowledge,
			Err: &wire.Error{Class: wire.ClassObject, Code: wire.CodeUnknownObject}},
	}
}

func frame(ts uint64, port uint32, nt wire.NetworkType, pos wire.Position, dst, src, data []byte) *wire.Message {
	return &wire.Message{
		Function: wire.FnFrame, Timestamp: ts, NetworkPort: port, NetworkType: nt, Position: pos,
		OriginalLength: uint32(len(data)), DestMAC: dst, SrcMAC: src, FrameData: data,
	}
}

func truncated(ts uint64, port uint32, nt wire.NetworkType, data []byte, original uint32) *wire.Message {
	m := frame(ts, port, nt, wire.PositionReceive, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		[]byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, data)
	m.OriginalLength = original
	return m
}

// npdu returns a BACnet NPDU carrying a ReadProperty request for the Present
// Value of Analog Input 5.
func npdu() []byte {
	return []byte{
		0x01, 0x04, // version, control: expecting reply
		0x00, 0x05, 0x01, 0x0C, // confirmed request, max apdu, invoke id, readProperty
		0x0C, 0x00, 0x00, 0x00, 0x05, // object identifier: analog-input 5
		0x19, 0x55, // property identifier: present-value
	}
}

// mstpFrame wraps data in an MS/TP frame with valid CRCs (Clause 9.3).
func mstpFrame(frameType, dst, src byte, data []byte) []byte {
	f := []byte{0x55, 0xFF, frameType, dst, src, byte(len(data) >> 8), byte(len(data))}
	f = append(f, mstpHeaderCRC(f[2:]))
	if len(data) > 0 {
		crc := mstpDataCRC(data)
		f = append(f, data...)
		f = append(f, byte(crc), byte(crc>>8))
	}
	return f
}

// mstpHeaderCRC implements the header CRC of Clause 9.5.6.
func mstpHeaderCRC(header []byte) byte {
	crc := uint16(0xFF)
	for _, b := range header {
		c := crc ^ uint16(b)
		c = c ^ (c << 1) ^ (c << 2) ^ (c << 3) ^ (c << 4) ^ (c << 5) ^ (c << 6) ^ (c << 7)
		crc = (c & 0xFE) ^ ((c >> 8) & 1)
	}
	return ^byte(crc)
}

// mstpDataCRC implements the data CRC of Clause 9.5.7.
func mstpDataCRC(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		c := uint16(b) ^ (crc & 0xFF)
		crc >>= 8
		crc ^= (c << 8) ^ (c << 3) ^ (c << 12) ^ (c >> 4) ^ (c & 0x0F) ^ ((c & 0x0F) << 7)
	}
	return ^crc
}
