package wire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "\t").Replace(s))
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// Golden vectors are encoded by hand from the message layouts in Clause YY.2.
func goldenVectors() []struct {
	name  string
	hex   string
	check func(*testing.T, *Message)
} {
	return []struct {
		name  string
		hex   string
		check func(*testing.T, *Message)
	}{
		{
			// YY.2.6.1, a BACnet/SC frame captured on the receive side.
			name: "frame secure-connect receive",
			hex: "11" + "0000000012345678" + "000003" + "0B" + "10" +
				"00000005" + "06" + "010203040506" + "06" + "0A0B0C0D0E0F" + "0102030405",
			check: func(t *testing.T, m *Message) {
				if m.Function != FnFrame {
					t.Errorf("Function = %v, want Frame", m.Function)
				}
				if m.Timestamp != 0x12345678 {
					t.Errorf("Timestamp = %d, want %d", m.Timestamp, 0x12345678)
				}
				if m.NetworkPort != 3 {
					t.Errorf("NetworkPort = %d, want 3", m.NetworkPort)
				}
				if m.NetworkType != NetworkSecureConnect {
					t.Errorf("NetworkType = %v, want secure-connect", m.NetworkType)
				}
				if m.Position != PositionReceive {
					t.Errorf("Position = %v, want receive", m.Position)
				}
				if got, want := len(m.FrameData), 5; got != want {
					t.Errorf("len(FrameData) = %d, want %d", got, want)
				}
				if m.OriginalLength != 5 {
					t.Errorf("OriginalLength = %d, want 5", m.OriginalLength)
				}
				if got := m.NetworkType.Dissector(); got != "bscvlc" {
					t.Errorf("Dissector = %q, want bscvlc", got)
				}
			},
		},
		{
			// A truncated MS/TP frame on the transmit side: the endpoint
			// shortened the LPDU to fit the WebSocket message (YY.4.1).
			name: "frame mstp transmit truncated",
			hex: "11" + "000000000000000A" + "000007" + "02" + "01" +
				"00000200" + "01" + "0C" + "01" + "05" + "55FF0500",
			check: func(t *testing.T, m *Message) {
				if m.NetworkType != NetworkMSTP {
					t.Errorf("NetworkType = %v, want mstp", m.NetworkType)
				}
				if m.Position != PositionTransmit {
					t.Errorf("Position = %v, want transmit", m.Position)
				}
				if !bytes.Equal(m.DestMAC, []byte{0x0C}) {
					t.Errorf("DestMAC = %x, want 0c", m.DestMAC)
				}
				if !bytes.Equal(m.SrcMAC, []byte{0x05}) {
					t.Errorf("SrcMAC = %x, want 05", m.SrcMAC)
				}
				if m.OriginalLength != 512 || len(m.FrameData) != 4 {
					t.Errorf("OriginalLength = %d, len(FrameData) = %d, want 512 and 4",
						m.OriginalLength, len(m.FrameData))
				}
				if got := m.NetworkType.Dissector(); got != "mstp" {
					t.Errorf("Dissector = %q, want mstp", got)
				}
			},
		},
		{
			name: "drop",
			hex:  "12" + "000003E8",
			check: func(t *testing.T, m *Message) {
				if m.DropCount != 1000 {
					t.Errorf("DropCount = %d, want 1000", m.DropCount)
				}
			},
		},
		{
			// An absent error indicates an ACK (YY.2.5.1).
			name: "acknowledge ack",
			hex:  "10",
			check: func(t *testing.T, m *Message) {
				if m.Err != nil {
					t.Errorf("Err = %v, want nil for an ACK", m.Err)
				}
			},
		},
		{
			// YY.3.1 requires OBJECT/UNKNOWN_OBJECT for an unknown network port.
			name: "acknowledge nak unknown object",
			hex:  "10" + "9101" + "911F",
			check: func(t *testing.T, m *Message) {
				if m.Err == nil {
					t.Fatal("Err = nil, want a NAK")
				}
				if m.Err.Class != ClassObject || m.Err.Code != CodeUnknownObject {
					t.Errorf("Err = class %d code %d, want %d and %d",
						m.Err.Class, m.Err.Code, ClassObject, CodeUnknownObject)
				}
			},
		},
		{
			// A filter installed on all network ports, both sides.
			name: "capture wildcard port both sides",
			hex:  "00" + "3FFFFF" + "11" + "090C",
			check: func(t *testing.T, m *Message) {
				if m.NetworkPort != AllNetworkPorts {
					t.Errorf("NetworkPort = %d, want %d", m.NetworkPort, AllNetworkPorts)
				}
				if m.Position != PositionBoth {
					t.Errorf("Position = %v, want both", m.Position)
				}
				if got, want := m.Filter.String(), "src 0c"; got != want {
					t.Errorf("Filter = %q, want %q", got, want)
				}
			},
		},
		{
			name: "monitor all diagnostics",
			hex:  "01" + "3FFFFF" + "07",
			check: func(t *testing.T, m *Message) {
				if m.Mask != MonitorAll {
					t.Errorf("Mask = %#02x, want %#02x", m.Mask, MonitorAll)
				}
			},
		},
		{
			// An accepted connection has no error field (YY.2.8.1).
			name: "connect accepted",
			hex: "13" + "0000000000001000" + "000003" + "0B" +
				"0E" + "0E" + "1C0A000005" + "0F" + "1ABAC0" + "0F",
			check: func(t *testing.T, m *Message) {
				if m.Err != nil {
					t.Errorf("Err = %v, want nil for an accepted connection", m.Err)
				}
				if m.Peer == nil {
					t.Fatal("Peer = nil")
				}
				if m.Peer.HostKind != HostIP || !bytes.Equal(m.Peer.HostIP, []byte{10, 0, 0, 5}) {
					t.Errorf("Peer host = %v/%x, want ip 0a000005", m.Peer.HostKind, m.Peer.HostIP)
				}
				if m.Peer.Port != 47808 {
					t.Errorf("Peer.Port = %d, want 47808", m.Peer.Port)
				}
			},
		},
		{
			// A device-initiated close with a TLS peer identity (YY.2.9.1).
			name: "disconnect by device with peer identity",
			hex: "14" + "0000000000002000" + "000003" + "0B" +
				"0E" + "0E" + "1C0A000005" + "0F" + "1ABAC0" + "0F" +
				"1D0E00" + "6261636E65743A2F2F31323334" +
				"2D20" + "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF" +
				"9101" + "911F",
			check: func(t *testing.T, m *Message) {
				if m.Peer == nil {
					t.Fatal("Peer = nil")
				}
				if m.Peer.SAN != "bacnet://1234" {
					t.Errorf("Peer.SAN = %q, want %q", m.Peer.SAN, "bacnet://1234")
				}
				if len(m.Peer.Fingerprint) != 32 {
					t.Errorf("len(Peer.Fingerprint) = %d, want 32", len(m.Peer.Fingerprint))
				}
				if m.Err == nil {
					t.Error("Err = nil, want the device-initiated close indication")
				}
			},
		},
	}
}

func TestGoldenDecode(t *testing.T) {
	for _, tc := range goldenVectors() {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex(t, tc.hex)
			m, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			tc.check(t, m)
			out, err := m.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !bytes.Equal(out, raw) {
				t.Errorf("round trip mismatch:\n in %x\nout %x", raw, out)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string
	}{
		{"empty", "", "empty message"},
		{"unknown function", "77", "unknown BDCC function"},
		{"truncated timestamp", "11" + "00000000", "truncated timestamp"},
		{"truncated network port", "11" + "0000000000000001" + "0000", "truncated network port"},
		{"network port above the instance maximum", "11" + "0000000000000001" + "FFFFFF", "exceeds 4194303"},
		{"reserved position", "11" + "0000000000000001" + "000003" + "0B" + "42", "reserved capture position"},
		{"both position in frame", "11" + "0000000000000001" + "000003" + "0B" + "11", "not valid in a Frame"},
		{"frame data exceeds original length", "11" + "0000000000000001" + "000003" + "0B" + "10" +
			"00000001" + "00" + "00" + "0102", "exceeds the original length"},
		{"truncated mac", "11" + "0000000000000001" + "000003" + "0B" + "10" + "00000005" + "06" + "0102", "truncated destination mac"},
		{"trailing octets after drop", "12" + "00000001" + "FF", "unexpected trailing octets"},
		{"capture filter unknown choice", "00" + "000001" + "10" + "A900", "unknown choice tag"},
		{"nak with a context tag", "10" + "0901", "expected an application-tagged enumerated"},
		{"connect without a peer", "13" + "0000000000000001" + "000003" + "0B", "capture peer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(mustHex(t, tc.hex))
			if err == nil {
				t.Fatal("Decode succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Decode error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestFunctionDirection(t *testing.T) {
	cases := []struct {
		f            Function
		fromEndpoint bool
	}{
		{FnCapture, false},
		{FnMonitor, false},
		{FnAcknowledge, true},
		{FnFrame, true},
		{FnDrop, true},
		{FnConnect, true},
		{FnDisconnect, true},
	}
	for _, tc := range cases {
		if got := tc.f.FromEndpoint(); got != tc.fromEndpoint {
			t.Errorf("%v.FromEndpoint() = %v, want %v", tc.f, got, tc.fromEndpoint)
		}
	}
}

func TestNetworkTypeDissector(t *testing.T) {
	cases := map[NetworkType]string{
		NetworkEthernet:      "bacnet",
		NetworkARCNET:        "bacnet",
		NetworkVirtual:       "bacnet",
		NetworkMSTP:          "mstp",
		NetworkIPv4:          "bvlc",
		NetworkIPv6:          "bvlc",
		NetworkSecureConnect: "bscvlc",
		NetworkPTP:           "data",
		NetworkLonTalk:       "data",
		NetworkSerial:        "data",
		NetworkZigbee:        "data",
		NetworkType(200):     "data",
	}
	for nt, want := range cases {
		if got := nt.Dissector(); got != want {
			t.Errorf("%v.Dissector() = %q, want %q", nt, got, want)
		}
	}
}

// FuzzDecode verifies that Decode does not panic and that decoded messages
// have a stable encoding. Clause 21 permits non-minimal integer and length
// encodings, so Encode may normalize the original bytes.
func FuzzDecode(f *testing.F) {
	for _, tc := range goldenVectors() {
		b, err := hex.DecodeString(strings.ReplaceAll(tc.hex, " ", ""))
		if err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return
		}
		first, err := m.Encode()
		if err != nil {
			t.Fatalf("decoded message failed to encode: %v", err)
		}
		again, err := Decode(first)
		if err != nil {
			t.Fatalf("re-encoded message failed to decode: %v (from %x)", err, data)
		}
		second, err := again.Encode()
		if err != nil {
			t.Fatalf("re-decoded message failed to encode: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("encoding is not stable:\nfirst  %x\nsecond %x", first, second)
		}
	})
}
