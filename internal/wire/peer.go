package wire

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// HostKind identifies the BACnetHostAddress choice for a peer (Clause 21).
type HostKind byte

const (
	HostNone HostKind = 0
	HostIP   HostKind = 1
	HostName HostKind = 2
)

// BACnetCapturePeer SEQUENCE tag numbers.
const (
	peerRemoteAddress byte = 0
	peerSAN           byte = 1
	peerFingerprint   byte = 2

	hostNPortHost byte = 0
	hostNPortPort byte = 1
)

// Peer is the BACnetCapturePeer in a Connect or Disconnect message.
//
// Only connection-oriented data links such as BACnet/SC and PTP report these
// messages (YY.2.8.1).
type Peer struct {
	HostKind HostKind
	HostIP   []byte // ip-address form
	HostName string // name form
	Port     uint16

	// SAN and Fingerprint identify the peer certificate. Data links without TLS
	// omit both fields.
	SAN         string
	Fingerprint []byte
}

func (p *Peer) String() string {
	var sb strings.Builder
	switch p.HostKind {
	case HostIP:
		if ip := net.IP(p.HostIP); len(p.HostIP) == 4 || len(p.HostIP) == 16 {
			fmt.Fprintf(&sb, "%s:%d", ip, p.Port)
		} else {
			fmt.Fprintf(&sb, "%x:%d", p.HostIP, p.Port)
		}
	case HostName:
		fmt.Fprintf(&sb, "%s:%d", p.HostName, p.Port)
	default:
		sb.WriteString("none")
	}
	if p.SAN != "" {
		fmt.Fprintf(&sb, " san=%s", p.SAN)
	}
	if len(p.Fingerprint) > 0 {
		fmt.Fprintf(&sb, " sha256=%s", hex.EncodeToString(p.Fingerprint))
	}
	return sb.String()
}

func (p *Peer) encode(b []byte) []byte {
	// remote-address [0] is a constructed BACnetHostNPort SEQUENCE.
	b = appendOpening(b, peerRemoteAddress)
	// host [0] encloses the BACnetHostAddress CHOICE.
	b = appendOpening(b, hostNPortHost)
	switch p.HostKind {
	case HostIP:
		b = appendOctetString(b, byte(HostIP), true, p.HostIP)
	case HostName:
		b = appendCharString(b, byte(HostName), true, p.HostName)
	default:
		b = appendTagHeader(b, byte(HostNone), true, 0)
	}
	b = appendClosing(b, hostNPortHost)
	b = appendUnsigned(b, hostNPortPort, true, uint32(p.Port))
	b = appendClosing(b, peerRemoteAddress)

	if p.SAN != "" {
		b = appendCharString(b, peerSAN, true, p.SAN)
	}
	if len(p.Fingerprint) > 0 {
		b = appendOctetString(b, peerFingerprint, true, p.Fingerprint)
	}
	return b
}

// decodePeer parses a BACnetCapturePeer at b[i]. It stops before an optional
// application-tagged BACnetError.
func decodePeer(b []byte, i int) (*Peer, int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return nil, i, fmt.Errorf("capture peer: %w", err)
	}
	if !t.context || !t.opening || t.number != peerRemoteAddress {
		return nil, i, fmt.Errorf("capture peer: expected opening tag 0 for remote-address")
	}
	p := &Peer{}
	i += t.hdrLen

	if i, err = p.decodeHostNPort(b, i); err != nil {
		return nil, i, err
	}
	if i, err = expectPeerClosing(b, i, peerRemoteAddress); err != nil {
		return nil, i, err
	}

	for i < len(b) {
		t, err := readTag(b, i)
		if err != nil {
			return nil, i, fmt.Errorf("capture peer: %w", err)
		}
		if !t.context {
			break // The optional BACnetError starts with an application tag.
		}
		switch t.number {
		case peerSAN:
			v, next := t.content(b, i)
			if len(v) == 0 {
				return nil, i, fmt.Errorf("capture peer: empty subject-alternative-name")
			}
			p.SAN, i = string(v[1:]), next // v[0] identifies the character set.
		case peerFingerprint:
			v, next := t.content(b, i)
			if len(v) != 32 {
				return nil, i, fmt.Errorf("capture peer: key-fingerprint-sha256 is %d octets, want 32", len(v))
			}
			p.Fingerprint, i = v, next
		default:
			return nil, i, fmt.Errorf("capture peer: unexpected context tag %d", t.number)
		}
	}
	return p, i, nil
}

func (p *Peer) decodeHostNPort(b []byte, i int) (int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return i, fmt.Errorf("host-n-port: %w", err)
	}
	if !t.context || !t.opening || t.number != hostNPortHost {
		return i, fmt.Errorf("host-n-port: expected opening tag 0 for host")
	}
	i += t.hdrLen

	ht, err := readTag(b, i)
	if err != nil {
		return i, fmt.Errorf("host-address: %w", err)
	}
	if !ht.context {
		return i, fmt.Errorf("host-address: expected a context tag")
	}
	v, next := ht.content(b, i)
	switch HostKind(ht.number) {
	case HostNone:
		p.HostKind = HostNone
	case HostIP:
		p.HostKind, p.HostIP = HostIP, v
	case HostName:
		if len(v) == 0 {
			return i, fmt.Errorf("host-address: empty name")
		}
		p.HostKind, p.HostName = HostName, string(v[1:])
	default:
		return i, fmt.Errorf("host-address: unknown choice tag %d", ht.number)
	}
	i = next

	if i, err = expectPeerClosing(b, i, hostNPortHost); err != nil {
		return i, err
	}

	pt, err := readTag(b, i)
	if err != nil {
		return i, fmt.Errorf("host-n-port: %w", err)
	}
	if !pt.context || pt.number != hostNPortPort || pt.opening || pt.closing {
		return i, fmt.Errorf("host-n-port: expected primitive tag 1 for port")
	}
	pv, next := pt.content(b, i)
	u, err := readUnsignedContent(pv)
	if err != nil {
		return i, fmt.Errorf("host-n-port port: %w", err)
	}
	if u > 0xFFFF {
		return i, fmt.Errorf("host-n-port: port %d exceeds 65535", u)
	}
	p.Port = uint16(u)
	return next, nil
}

func expectPeerClosing(b []byte, i int, number byte) (int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return i, err
	}
	if !t.context || !t.closing || t.number != number {
		return i, fmt.Errorf("capture peer: expected closing tag %d at offset %d", number, i)
	}
	return i + t.hdrLen, nil
}

func (e *Error) encode(b []byte) []byte {
	b = appendUnsigned(b, appTagEnumerated, false, e.Class)
	return appendUnsigned(b, appTagEnumerated, false, e.Code)
}

// decodeError parses the application-tagged class and code of a BACnetError.
func decodeError(b []byte, i int) (*Error, int, error) {
	class, i, err := decodeEnumerated(b, i, "error class")
	if err != nil {
		return nil, i, err
	}
	code, i, err := decodeEnumerated(b, i, "error code")
	if err != nil {
		return nil, i, err
	}
	return &Error{Class: class, Code: code}, i, nil
}

func decodeEnumerated(b []byte, i int, what string) (uint32, int, error) {
	t, err := readTag(b, i)
	if err != nil {
		return 0, i, fmt.Errorf("%s: %w", what, err)
	}
	if t.context || t.number != appTagEnumerated || t.opening || t.closing {
		return 0, i, fmt.Errorf("%s: expected an application-tagged enumerated value", what)
	}
	v, next := t.content(b, i)
	u, err := readUnsignedContent(v)
	if err != nil {
		return 0, i, fmt.Errorf("%s: %w", what, err)
	}
	return u, next, nil
}
