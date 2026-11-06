// Package wire encodes and decodes the BACnet Diagnostic Connection Control
// messages defined by Annex YY of draft proposal 135-2024df.
//
// Each encoded message occupies one WebSocket binary data frame (YY.5.2).
// Integers use most-significant-octet-first order unless noted otherwise (YY.2.1).
package wire

import "fmt"

// Function identifies the BDCC message type (Table YY-1).
type Function byte

const (
	FnCapture     Function = 0x00
	FnMonitor     Function = 0x01
	FnAcknowledge Function = 0x10
	FnFrame       Function = 0x11
	FnDrop        Function = 0x12
	FnConnect     Function = 0x13
	FnDisconnect  Function = 0x14
)

var fnNames = map[Function]string{
	FnCapture:     "Capture",
	FnMonitor:     "Monitor",
	FnAcknowledge: "Acknowledge",
	FnFrame:       "Frame",
	FnDrop:        "Drop",
	FnConnect:     "Connect",
	FnDisconnect:  "Disconnect",
}

func (f Function) String() string {
	if n, ok := fnNames[f]; ok {
		return n
	}
	return fmt.Sprintf("BDCC-Function(0x%02X)", byte(f))
}

// FromEndpoint reports whether f is an endpoint-to-tool function. The most
// significant nibble specifies the direction (YY.2, YY.4).
func (f Function) FromEndpoint() bool { return byte(f)>>4 == 1 }

// Position identifies a capture point on a network port (Table YY-3).
type Position byte

const (
	PositionReceive  Position = 0x10
	PositionTransmit Position = 0x01
	PositionBoth     Position = 0x11
)

func (p Position) String() string {
	switch p {
	case PositionReceive:
		return "receive"
	case PositionTransmit:
		return "transmit"
	case PositionBoth:
		return "both"
	default:
		return fmt.Sprintf("Position(0x%02X)", byte(p))
	}
}

// valid reports whether p is a capture position defined by Table YY-3.
func (p Position) valid() bool {
	return p == PositionReceive || p == PositionTransmit || p == PositionBoth
}

// Monitor mask bits (YY.2.4.1). Bits 3 through 7 are reserved.
const (
	MonitorDisconnect byte = 1 << 0 // emit Disconnect messages for this port
	MonitorRejected   byte = 1 << 1 // emit Connect messages for rejects
	MonitorAccepted   byte = 1 << 2 // emit Connect messages for accepts
	MonitorAll        byte = MonitorDisconnect | MonitorRejected | MonitorAccepted
)

// AllNetworkPorts is the wildcard object instance for every network port
// (YY.2.3.1).
const AllNetworkPorts uint32 = 4194303

// Message is a decoded BDCC message. Function determines which fields apply.
type Message struct {
	Function Function

	// Timestamp is the number of microseconds since the endpoint's fixed,
	// unspecified connection epoch (YY.2.2).
	Timestamp uint64

	NetworkPort uint32      // instance number, three octets
	NetworkType NetworkType // data link type of the network port
	Position    Position

	// OriginalLength is the frame length before truncation. It exceeds
	// len(FrameData) when the endpoint shortened the LPDU (YY.2.6.1, YY.4.1).
	OriginalLength uint32
	DestMAC        []byte
	SrcMAC         []byte
	FrameData      []byte

	Mask      byte   // Monitor
	DropCount uint32 // Drop
	Filter    Filter // Capture
	Peer      *Peer  // Connect, Disconnect

	// Err is the optional BACnetError. It indicates a NAK, a rejected
	// connection, or a device-initiated disconnect, depending on Function
	// (YY.2.5.1, YY.2.8.1, YY.2.9.1).
	Err *Error
}

// envelope defines the fields used by each function.
type envelope struct {
	timestamp   bool
	port        bool // three-octet network port instance
	networkType bool // one-octet BACnetNetworkType
	position    bool
	frame       bool // original length, both MACs, and the frame data
	mask        bool
	dropCount   bool
	filter      bool
	peer        bool
	optionalErr bool
}

var envelopes = map[Function]envelope{
	FnCapture:     {port: true, position: true, filter: true},
	FnMonitor:     {port: true, mask: true},
	FnAcknowledge: {optionalErr: true},
	FnFrame:       {timestamp: true, port: true, networkType: true, position: true, frame: true},
	FnDrop:        {dropCount: true},
	FnConnect:     {timestamp: true, port: true, networkType: true, peer: true, optionalErr: true},
	FnDisconnect:  {timestamp: true, port: true, networkType: true, peer: true, optionalErr: true},
}

// Decode parses one complete BDCC message and returns *DecodeError on failure.
func Decode(b []byte) (*Message, error) {
	if len(b) == 0 {
		return nil, &DecodeError{Detail: "empty message"}
	}
	m := &Message{Function: Function(b[0])}
	env, known := envelopes[m.Function]
	if !known {
		return nil, &DecodeError{Function: m.Function, Detail: "unknown BDCC function"}
	}

	i := 1
	derr := func(detail string) error {
		return &DecodeError{Function: m.Function, Offset: i, Detail: detail}
	}
	short := func(field string, n int) error {
		return derr(fmt.Sprintf("truncated %s: %d octets needed, %d remain", field, n, len(b)-i))
	}

	if env.timestamp {
		if i+8 > len(b) {
			return nil, short("timestamp", 8)
		}
		for _, c := range b[i : i+8] {
			m.Timestamp = m.Timestamp<<8 | uint64(c)
		}
		i += 8
	}
	if env.port {
		if i+3 > len(b) {
			return nil, short("network port", 3)
		}
		m.NetworkPort = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		// A three-octet field can exceed the BACnet object-instance limit.
		if m.NetworkPort > AllNetworkPorts {
			return nil, derr(fmt.Sprintf("network port %d exceeds %d", m.NetworkPort, AllNetworkPorts))
		}
		i += 3
	}
	if env.networkType {
		if i+1 > len(b) {
			return nil, short("network type", 1)
		}
		m.NetworkType = NetworkType(b[i])
		i++
	}
	if env.position {
		if i+1 > len(b) {
			return nil, short("position", 1)
		}
		m.Position = Position(b[i])
		if !m.Position.valid() {
			return nil, derr(fmt.Sprintf("reserved capture position 0x%02X", byte(m.Position)))
		}
		// A frame has one capture position, not both (YY.2.6.1).
		if m.Function == FnFrame && m.Position == PositionBoth {
			return nil, derr("capture position X'11' is not valid in a Frame message")
		}
		i++
	}
	if env.frame {
		if i+4 > len(b) {
			return nil, short("original length", 4)
		}
		m.OriginalLength = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		i += 4
		var err error
		if m.DestMAC, i, err = decodeMAC(b, i, "destination"); err != nil {
			return nil, &DecodeError{Function: m.Function, Offset: i, Detail: err.Error()}
		}
		if m.SrcMAC, i, err = decodeMAC(b, i, "source"); err != nil {
			return nil, &DecodeError{Function: m.Function, Offset: i, Detail: err.Error()}
		}
		// Frame Data occupies the rest of the message.
		m.FrameData = b[i:len(b):len(b)]
		if uint32(len(m.FrameData)) > m.OriginalLength {
			return nil, derr(fmt.Sprintf("frame data of %d octets exceeds the original length of %d",
				len(m.FrameData), m.OriginalLength))
		}
		return m, nil
	}
	if env.mask {
		if i+1 > len(b) {
			return nil, short("mask", 1)
		}
		m.Mask = b[i]
		i++
	}
	if env.dropCount {
		if i+4 > len(b) {
			return nil, short("frame count", 4)
		}
		m.DropCount = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		i += 4
	}
	if env.filter {
		f, n, err := decodeFilter(b, i)
		if err != nil {
			return nil, &DecodeError{Function: m.Function, Offset: i, Detail: err.Error()}
		}
		m.Filter, i = f, n
	}
	if env.peer {
		p, n, err := decodePeer(b, i)
		if err != nil {
			return nil, &DecodeError{Function: m.Function, Offset: i, Detail: err.Error()}
		}
		m.Peer, i = p, n
	}
	if env.optionalErr && i < len(b) {
		e, n, err := decodeError(b, i)
		if err != nil {
			return nil, &DecodeError{Function: m.Function, Offset: i, Detail: err.Error()}
		}
		m.Err, i = e, n
	}
	if i != len(b) {
		return nil, derr(fmt.Sprintf("%d unexpected trailing octets", len(b)-i))
	}
	return m, nil
}

// decodeMAC reads a one-octet length followed by that many address octets.
func decodeMAC(b []byte, i int, which string) ([]byte, int, error) {
	if i >= len(b) {
		return nil, i, fmt.Errorf("truncated %s mac length", which)
	}
	n := int(b[i])
	i++
	if i+n > len(b) {
		return nil, i, fmt.Errorf("truncated %s mac: %d octets needed, %d remain", which, n, len(b)-i)
	}
	return b[i : i+n : i+n], i + n, nil
}

// Encode serializes m. It is the inverse of Decode for accepted messages.
func (m *Message) Encode() ([]byte, error) {
	env, known := envelopes[m.Function]
	if !known {
		return nil, fmt.Errorf("wire: encode: unknown BDCC function 0x%02X", byte(m.Function))
	}
	b := make([]byte, 0, 18+len(m.DestMAC)+len(m.SrcMAC)+len(m.FrameData))
	b = append(b, byte(m.Function))

	if env.timestamp {
		b = append(b, byte(m.Timestamp>>56), byte(m.Timestamp>>48), byte(m.Timestamp>>40), byte(m.Timestamp>>32),
			byte(m.Timestamp>>24), byte(m.Timestamp>>16), byte(m.Timestamp>>8), byte(m.Timestamp))
	}
	if env.port {
		if m.NetworkPort > AllNetworkPorts {
			return nil, fmt.Errorf("wire: encode %v: network port %d exceeds %d", m.Function, m.NetworkPort, AllNetworkPorts)
		}
		b = append(b, byte(m.NetworkPort>>16), byte(m.NetworkPort>>8), byte(m.NetworkPort))
	}
	if env.networkType {
		b = append(b, byte(m.NetworkType))
	}
	if env.position {
		if !m.Position.valid() {
			return nil, fmt.Errorf("wire: encode %v: reserved capture position 0x%02X", m.Function, byte(m.Position))
		}
		if m.Function == FnFrame && m.Position == PositionBoth {
			return nil, fmt.Errorf("wire: encode Frame: capture position X'11' is not valid")
		}
		b = append(b, byte(m.Position))
	}
	if env.frame {
		if uint32(len(m.FrameData)) > m.OriginalLength {
			return nil, fmt.Errorf("wire: encode Frame: %d octets of frame data exceed the original length of %d",
				len(m.FrameData), m.OriginalLength)
		}
		if len(m.DestMAC) > 255 || len(m.SrcMAC) > 255 {
			return nil, fmt.Errorf("wire: encode Frame: mac address longer than 255 octets")
		}
		b = append(b, byte(m.OriginalLength>>24), byte(m.OriginalLength>>16), byte(m.OriginalLength>>8), byte(m.OriginalLength))
		b = append(b, byte(len(m.DestMAC)))
		b = append(b, m.DestMAC...)
		b = append(b, byte(len(m.SrcMAC)))
		b = append(b, m.SrcMAC...)
		return append(b, m.FrameData...), nil
	}
	if env.mask {
		b = append(b, m.Mask)
	}
	if env.dropCount {
		b = append(b, byte(m.DropCount>>24), byte(m.DropCount>>16), byte(m.DropCount>>8), byte(m.DropCount))
	}
	if env.filter {
		if m.Filter == nil {
			return nil, fmt.Errorf("wire: encode Capture: a capture filter is required")
		}
		b = m.Filter.encode(b)
	}
	if env.peer {
		if m.Peer == nil {
			return nil, fmt.Errorf("wire: encode %v: a peer is required", m.Function)
		}
		b = m.Peer.encode(b)
	}
	if env.optionalErr && m.Err != nil {
		b = m.Err.encode(b)
	}
	return b, nil
}
