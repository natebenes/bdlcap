// Package pcapng writes the pcapng blocks needed for a live extcap capture.
//
// Each block is written without buffering so Wireshark receives packets as
// they arrive on the extcap FIFO.
package pcapng

import (
	"fmt"
	"io"
	"time"
)

// Private-use link types LINKTYPE_USER0 through LINKTYPE_USER15. bdlcap uses
// one until BDCC receives a registered link type.
const (
	LinkTypeUser0  uint16 = 147
	LinkTypeUser15 uint16 = 162
)

// Block types (pcapng specification section 4).
const (
	blockSectionHeader      uint32 = 0x0A0D0D0A
	blockInterfaceDesc      uint32 = 0x00000001
	blockEnhancedPacket     uint32 = 0x00000006
	byteOrderMagic          uint32 = 0x1A2B3C4D
	sectionLengthUnknown    uint64 = 0xFFFFFFFFFFFFFFFF
	interfaceIDDefaultIface uint32 = 0
)

// Option codes used here (pcapng specification sections 3.5, 4.1, 4.2).
const (
	optEndOfOpt      uint16 = 0
	optIfName        uint16 = 2
	optIfDescription uint16 = 3
	optIfTSResol     uint16 = 9
	optShbUserAppl   uint16 = 4
)

// tsResolMicros selects microsecond timestamps to match BDCC (YY.2.2).
const tsResolMicros byte = 6

// Writer emits pcapng data for one capture interface.
type Writer struct {
	w   io.Writer
	buf []byte
}

// NewWriter writes the initial blocks and returns a Writer for packet data.
func NewWriter(w io.Writer, linkType uint16, application, name, description string) (*Writer, error) {
	pw := &Writer{w: w}
	if err := pw.writeSectionHeader(application); err != nil {
		return nil, err
	}
	if err := pw.writeInterfaceDescription(linkType, name, description); err != nil {
		return nil, err
	}
	return pw, nil
}

// WritePacket writes one packet. originalLen is its length before truncation
// and must be at least len(data).
func (w *Writer) WritePacket(ts time.Time, originalLen int, data []byte) error {
	if originalLen < len(data) {
		return fmt.Errorf("pcapng: original length %d is below the captured length %d", originalLen, len(data))
	}
	micros := uint64(ts.UnixMicro())

	w.buf = w.buf[:0]
	w.buf = appendU32(w.buf, blockEnhancedPacket)
	lengthAt := len(w.buf)
	w.buf = appendU32(w.buf, 0) // block total length, filled in below
	w.buf = appendU32(w.buf, interfaceIDDefaultIface)
	w.buf = appendU32(w.buf, uint32(micros>>32))
	w.buf = appendU32(w.buf, uint32(micros))
	w.buf = appendU32(w.buf, uint32(len(data)))
	w.buf = appendU32(w.buf, uint32(originalLen))
	w.buf = append(w.buf, data...)
	w.buf = pad32(w.buf)
	w.buf = w.finish(lengthAt)
	return w.flush()
}

func (w *Writer) writeSectionHeader(application string) error {
	w.buf = w.buf[:0]
	w.buf = appendU32(w.buf, blockSectionHeader)
	lengthAt := len(w.buf)
	w.buf = appendU32(w.buf, 0)
	w.buf = appendU32(w.buf, byteOrderMagic)
	w.buf = appendU16(w.buf, 1) // major version
	w.buf = appendU16(w.buf, 0) // minor version
	w.buf = appendU64(w.buf, sectionLengthUnknown)
	if application != "" {
		w.buf = appendOption(w.buf, optShbUserAppl, []byte(application))
	}
	w.buf = appendEndOfOptions(w.buf)
	w.buf = w.finish(lengthAt)
	return w.flush()
}

func (w *Writer) writeInterfaceDescription(linkType uint16, name, description string) error {
	w.buf = w.buf[:0]
	w.buf = appendU32(w.buf, blockInterfaceDesc)
	lengthAt := len(w.buf)
	w.buf = appendU32(w.buf, 0)
	w.buf = appendU16(w.buf, linkType)
	w.buf = appendU16(w.buf, 0) // reserved
	w.buf = appendU32(w.buf, 0) // snap length: no limit imposed by this tool
	if name != "" {
		w.buf = appendOption(w.buf, optIfName, []byte(name))
	}
	if description != "" {
		w.buf = appendOption(w.buf, optIfDescription, []byte(description))
	}
	w.buf = appendOption(w.buf, optIfTSResol, []byte{tsResolMicros})
	w.buf = appendEndOfOptions(w.buf)
	w.buf = w.finish(lengthAt)
	return w.flush()
}

// finish records the block length in the header and trailer.
func (w *Writer) finish(lengthAt int) []byte {
	total := uint32(len(w.buf) + 4)
	putU32(w.buf[lengthAt:], total)
	return appendU32(w.buf, total)
}

func (w *Writer) flush() error {
	if _, err := w.w.Write(w.buf); err != nil {
		return fmt.Errorf("pcapng: writing block: %w", err)
	}
	return nil
}

func appendOption(b []byte, code uint16, value []byte) []byte {
	b = appendU16(b, code)
	b = appendU16(b, uint16(len(value)))
	b = append(b, value...)
	return pad32(b)
}

func appendEndOfOptions(b []byte) []byte {
	b = appendU16(b, optEndOfOpt)
	return appendU16(b, 0)
}

// pad32 pads b with zeroes to the next 32-bit boundary.
func pad32(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
