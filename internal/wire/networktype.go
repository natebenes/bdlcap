package wire

import "fmt"

// NetworkType is a BACnetNetworkType value that identifies how to decode Frame
// Data (Clause 21 and Table YY-5).
type NetworkType byte

// BACnetNetworkType values. ASHRAE reserves values 0 through 63; values 64
// through 255 are available to others (Clause 21).
const (
	NetworkEthernet      NetworkType = 0
	NetworkARCNET        NetworkType = 1
	NetworkMSTP          NetworkType = 2
	NetworkPTP           NetworkType = 3
	NetworkLonTalk       NetworkType = 4
	NetworkIPv4          NetworkType = 5
	NetworkZigbee        NetworkType = 6
	NetworkVirtual       NetworkType = 7
	NetworkIPv6          NetworkType = 9
	NetworkSerial        NetworkType = 10
	NetworkSecureConnect NetworkType = 11
)

var networkTypeNames = map[NetworkType]string{
	NetworkEthernet:      "ethernet",
	NetworkARCNET:        "arcnet",
	NetworkMSTP:          "mstp",
	NetworkPTP:           "ptp",
	NetworkLonTalk:       "lontalk",
	NetworkIPv4:          "ipv4",
	NetworkZigbee:        "zigbee",
	NetworkVirtual:       "virtual",
	NetworkIPv6:          "ipv6",
	NetworkSerial:        "serial",
	NetworkSecureConnect: "secure-connect",
}

func (t NetworkType) String() string {
	if n, ok := networkTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("BACnetNetworkType(%d)", byte(t))
}

// Dissector returns the Wireshark dissector for this network type. Types with
// no suitable dissector use the raw-data one: PTP, whose frames Table YY-5
// defines but Wireshark does not decode, and types the table does not list.
// Table YY-5 does not list virtual either; bdlcap treats its frames as NPDUs.
//
// Keep this mapping synchronized with wireshark/bdc.lua.
func (t NetworkType) Dissector() string {
	switch t {
	case NetworkMSTP:
		return "mstp"
	case NetworkIPv4, NetworkIPv6:
		return "bvlc"
	case NetworkSecureConnect:
		return "bscvlc"
	case NetworkEthernet, NetworkARCNET, NetworkVirtual:
		return "bacnet"
	default:
		return "data"
	}
}
