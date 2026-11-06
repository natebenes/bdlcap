package wire

import (
	"fmt"
	"strings"
)

// Filter is a BACnetCaptureFilter evaluated against each LPDU. A TRUE result
// sends the LPDU to the diagnostic connection (YY.3, YY.3.1).
//
// Build filters with the constructors below or ParseFilter. Overlapping
// filters produce duplicate Frame messages because filters cannot be removed
// individually (YY.1, YY.3.1).
type Filter interface {
	encode(b []byte) []byte

	// String renders the filter in the expression syntax accepted by
	// ParseFilter.
	String() string
}

// BACnetCaptureFilter CHOICE tag numbers.
const (
	filterSourceMAC    byte = 0
	filterDestMAC      byte = 1
	filterDatalinkType byte = 2
	filterNetworkType  byte = 3
	filterAPDUType     byte = 4
	filterConfirmed    byte = 5
	filterUnconfirmed  byte = 6
	filterNot          byte = 7
	filterAnd          byte = 8
	filterOr           byte = 9

	// Operand tags for logical-and and logical-or. Each CHOICE operand is
	// enclosed by opening and closing tags.
	filterLeft  byte = 0
	filterRight byte = 1
)

type macFilter struct {
	tag byte
	mac []byte
}

func (f macFilter) encode(b []byte) []byte { return appendOctetString(b, f.tag, true, f.mac) }

func (f macFilter) String() string {
	name := "src"
	if f.tag == filterDestMAC {
		name = "dst"
	}
	return name + " " + formatMAC(f.mac)
}

type uintFilter struct {
	tag byte
	val uint32
}

func (f uintFilter) encode(b []byte) []byte { return appendUnsigned(b, f.tag, true, f.val) }

func (f uintFilter) String() string {
	var name string
	switch f.tag {
	case filterDatalinkType:
		name = "dlmsg"
	case filterNetworkType:
		name = "netmsg"
	case filterAPDUType:
		name = "apdu"
	case filterConfirmed:
		name = "confirmed"
	default:
		name = "unconfirmed"
	}
	return fmt.Sprintf("%s %d", name, f.val)
}

type notFilter struct{ inner Filter }

func (f notFilter) encode(b []byte) []byte {
	b = appendOpening(b, filterNot)
	b = f.inner.encode(b)
	return appendClosing(b, filterNot)
}

func (f notFilter) String() string { return "not (" + f.inner.String() + ")" }

type binaryFilter struct {
	tag         byte
	left, right Filter
}

func (f binaryFilter) encode(b []byte) []byte {
	b = appendOpening(b, f.tag)
	b = appendOpening(b, filterLeft)
	b = f.left.encode(b)
	b = appendClosing(b, filterLeft)
	b = appendOpening(b, filterRight)
	b = f.right.encode(b)
	b = appendClosing(b, filterRight)
	return appendClosing(b, f.tag)
}

func (f binaryFilter) String() string {
	op := " and "
	if f.tag == filterOr {
		op = " or "
	}
	return "(" + f.left.String() + op + f.right.String() + ")"
}

// SrcMAC matches the source MAC address. Locally generated LPDUs use the
// network port's MAC address (YY.3.1.1).
func SrcMAC(mac []byte) Filter { return macFilter{filterSourceMAC, mac} }

// DstMAC matches the destination MAC address. LPDUs addressed to the local
// device use the network port's MAC address (YY.3.1.2).
func DstMAC(mac []byte) Filter { return macFilter{filterDestMAC, mac} }

// DatalinkMessageType matches the datalink-specific message type of Table
// YY-4: the frame type for MS/TP and PTP, and the BVLC function for
// BACnet/IP, BACnet/IPv6, and BACnet/SC (YY.3.1.3).
func DatalinkMessageType(v uint32) Filter { return uintFilter{filterDatalinkType, v} }

// NetworkMessageType matches the NPDU Message Type field. It is FALSE when
// the LPDU carries no NPDU, or the NPDU has no message type (YY.3.1.4).
func NetworkMessageType(v uint8) Filter { return uintFilter{filterNetworkType, uint32(v)} }

// APDUType matches the APDU pdu-type field. It is FALSE when the LPDU
// carries no APDU (YY.3.1.5).
func APDUType(v uint8) Filter { return uintFilter{filterAPDUType, uint32(v)} }

// ConfirmedService matches the service choice of a ConfirmedRequest, SimpleACK,
// or ComplexACK, or the error choice of an Error PDU (YY.3.1.6).
func ConfirmedService(v uint8) Filter { return uintFilter{filterConfirmed, uint32(v)} }

// UnconfirmedService matches the service-choice of an UnconfirmedRequest
// (YY.3.1.7).
func UnconfirmedService(v uint8) Filter { return uintFilter{filterUnconfirmed, uint32(v)} }

// Not inverts f (YY.3.1.8).
func Not(f Filter) Filter { return notFilter{f} }

// And is TRUE when both operands are TRUE (YY.3.1.9).
func And(left, right Filter) Filter { return binaryFilter{filterAnd, left, right} }

// Or is TRUE when either operand is TRUE (YY.3.1.10).
func Or(left, right Filter) Filter { return binaryFilter{filterOr, left, right} }

// MatchAll returns a filter that is TRUE for every LPDU.
//
// BACnetCaptureFilter has no "match everything" choice. This filter negates
// the contradiction that an LPDU both has and does not have an APDU type of 0.
func MatchAll() Filter {
	return Not(And(APDUType(0), Not(APDUType(0))))
}

func formatMAC(mac []byte) string {
	if len(mac) == 0 {
		return "''"
	}
	var sb strings.Builder
	for i, c := range mac {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// decodeFilter parses one BACnetCaptureFilter beginning at b[i] and returns
// the offset just past it.
func decodeFilter(b []byte, i int) (Filter, int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return nil, i, err
	}
	if !t.context {
		return nil, i, fmt.Errorf("capture filter: expected a context tag, got application tag %d", t.number)
	}
	switch t.number {
	case filterSourceMAC, filterDestMAC:
		if t.opening || t.closing {
			return nil, i, fmt.Errorf("capture filter: mac address tag %d is constructed", t.number)
		}
		v, next := t.content(b, i)
		return macFilter{t.number, v}, next, nil

	case filterDatalinkType, filterNetworkType, filterAPDUType, filterConfirmed, filterUnconfirmed:
		if t.opening || t.closing {
			return nil, i, fmt.Errorf("capture filter: tag %d is constructed", t.number)
		}
		v, next := t.content(b, i)
		u, err := readUnsignedContent(v)
		if err != nil {
			return nil, i, fmt.Errorf("capture filter tag %d: %w", t.number, err)
		}
		if t.number == filterAPDUType && u > 7 {
			return nil, i, fmt.Errorf("capture filter: apdu-type %d is outside 0..7", u)
		}
		return uintFilter{t.number, u}, next, nil

	case filterNot:
		if !t.opening {
			return nil, i, fmt.Errorf("capture filter: logical-not is not an opening tag")
		}
		inner, next, err := decodeFilter(b, i+t.hdrLen)
		if err != nil {
			return nil, i, err
		}
		next, err = expectClosing(b, next, filterNot)
		if err != nil {
			return nil, i, err
		}
		return notFilter{inner}, next, nil

	case filterAnd, filterOr:
		if !t.opening {
			return nil, i, fmt.Errorf("capture filter: tag %d is not an opening tag", t.number)
		}
		left, next, err := decodeOperand(b, i+t.hdrLen, filterLeft)
		if err != nil {
			return nil, i, err
		}
		right, next, err := decodeOperand(b, next, filterRight)
		if err != nil {
			return nil, i, err
		}
		next, err = expectClosing(b, next, t.number)
		if err != nil {
			return nil, i, err
		}
		return binaryFilter{t.number, left, right}, next, nil
	}
	return nil, i, fmt.Errorf("capture filter: unknown choice tag %d", t.number)
}

// decodeOperand parses a CHOICE operand enclosed by opening and closing tags.
func decodeOperand(b []byte, i int, number byte) (Filter, int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return nil, i, err
	}
	if !t.context || !t.opening || t.number != number {
		return nil, i, fmt.Errorf("capture filter: expected opening tag %d", number)
	}
	f, next, err := decodeFilter(b, i+t.hdrLen)
	if err != nil {
		return nil, i, err
	}
	next, err = expectClosing(b, next, number)
	if err != nil {
		return nil, i, err
	}
	return f, next, nil
}

func expectClosing(b []byte, i int, number byte) (int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return i, err
	}
	if !t.context || !t.closing || t.number != number {
		return i, fmt.Errorf("capture filter: expected closing tag %d at offset %d", number, i)
	}
	return i + t.hdrLen, nil
}
