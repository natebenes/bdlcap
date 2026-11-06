package wire

import "fmt"

// BACnetCaptureFilter, BACnetCapturePeer, and BACnetError use the variable-length
// application and context tags defined by Clauses 20.2 and 21 (YY.2.3).

// Length/Value/Type codes of a tag octet (Clause 20.2.1.3).
const (
	lvtExtended byte = 5
	lvtOpening  byte = 6
	lvtClosing  byte = 7
)

// Application tag for the ENUMERATED values in BACnetError (Clause 20.2.1.4).
const appTagEnumerated byte = 9

// Character string encoding 0 is ANSI X3.4 / UTF-8 (Clause 20.2.9).
const charsetUTF8 byte = 0

// appendTagHeader appends a tag header. Tag numbers above 14 use the extended
// form (Clause 20.2.1.2).
func appendTagHeader(b []byte, number byte, context bool, lvt byte) []byte {
	var class byte
	if context {
		class = 0x08
	}
	if number <= 14 {
		return append(b, number<<4|class|lvt)
	}
	return append(b, 0xF0|class|lvt, number)
}

// appendHeaderLen appends a primitive tag header for n content octets
// (Clause 20.2.1.3.1).
func appendHeaderLen(b []byte, number byte, context bool, n int) []byte {
	if n <= 4 {
		return appendTagHeader(b, number, context, byte(n))
	}
	b = appendTagHeader(b, number, context, lvtExtended)
	switch {
	case n < 254:
		return append(b, byte(n))
	case n <= 0xFFFF:
		return append(b, 254, byte(n>>8), byte(n))
	default:
		return append(b, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func appendOpening(b []byte, number byte) []byte {
	return appendTagHeader(b, number, true, lvtOpening)
}

func appendClosing(b []byte, number byte) []byte {
	return appendTagHeader(b, number, true, lvtClosing)
}

func appendOctetString(b []byte, number byte, context bool, v []byte) []byte {
	b = appendHeaderLen(b, number, context, len(v))
	return append(b, v...)
}

// unsignedOctets returns the minimum encoded width of v (Clause 20.2.4).
func unsignedOctets(v uint32) int {
	switch {
	case v <= 0xFF:
		return 1
	case v <= 0xFFFF:
		return 2
	case v <= 0xFFFFFF:
		return 3
	default:
		return 4
	}
}

func appendUnsigned(b []byte, number byte, context bool, v uint32) []byte {
	n := unsignedOctets(v)
	b = appendHeaderLen(b, number, context, n)
	for shift := (n - 1) * 8; shift >= 0; shift -= 8 {
		b = append(b, byte(v>>uint(shift)))
	}
	return b
}

func appendCharString(b []byte, number byte, context bool, s string) []byte {
	b = appendHeaderLen(b, number, context, len(s)+1)
	b = append(b, charsetUTF8)
	return append(b, s...)
}

// tag describes a decoded tag header and its content length.
type tag struct {
	number  byte
	context bool
	opening bool
	closing bool
	length  int // content length; zero for opening/closing tags
	hdrLen  int // octets consumed by the tag header itself
}

// readTag decodes the tag beginning at b[i].
func readTag(b []byte, i int) (tag, error) {
	if i >= len(b) {
		return tag{}, fmt.Errorf("truncated tag at offset %d", i)
	}
	start := i
	t := tag{number: b[i] >> 4, context: b[i]&0x08 != 0}
	lvt := b[i] & 0x07
	i++
	if t.number == 0x0F {
		if i >= len(b) {
			return tag{}, fmt.Errorf("truncated extended tag number at offset %d", i)
		}
		t.number = b[i]
		i++
	}
	switch lvt {
	case lvtOpening:
		t.opening = true
	case lvtClosing:
		t.closing = true
	case lvtExtended:
		if i >= len(b) {
			return tag{}, fmt.Errorf("truncated extended length at offset %d", i)
		}
		switch n := b[i]; {
		case n < 254:
			t.length = int(n)
			i++
		case n == 254:
			if i+3 > len(b) {
				return tag{}, fmt.Errorf("truncated 16-bit length at offset %d", i)
			}
			t.length = int(b[i+1])<<8 | int(b[i+2])
			i += 3
		default:
			if i+5 > len(b) {
				return tag{}, fmt.Errorf("truncated 32-bit length at offset %d", i)
			}
			t.length = int(b[i+1])<<24 | int(b[i+2])<<16 | int(b[i+3])<<8 | int(b[i+4])
			i += 5
		}
	default:
		t.length = int(lvt)
	}
	t.hdrLen = i - start
	if t.length < 0 || i+t.length > len(b) {
		return tag{}, fmt.Errorf("tag %d at offset %d claims %d octets, %d remain", t.number, start, t.length, len(b)-i)
	}
	return t, nil
}

// content returns the tag content and the following offset.
func (t tag) content(b []byte, i int) ([]byte, int) {
	start := i + t.hdrLen
	end := start + t.length
	return b[start:end:end], end
}

// readUnsignedContent decodes an unsigned integer from content octets.
func readUnsignedContent(v []byte) (uint32, error) {
	if len(v) == 0 || len(v) > 4 {
		return 0, fmt.Errorf("unsigned value of %d octets", len(v))
	}
	var u uint32
	for _, c := range v {
		u = u<<8 | uint32(c)
	}
	return u, nil
}
