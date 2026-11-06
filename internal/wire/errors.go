package wire

import "fmt"

// DecodeError reports a malformed BDCC message and its location.
type DecodeError struct {
	Function Function // the function octet, if one was read
	Offset   int      // octet offset at which decoding failed
	Detail   string
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("wire: decode %v at offset %d: %s", e.Function, e.Offset, e.Detail)
}

// Error is the BACnet error class and code from a NAK, rejected Connect, or
// device-initiated Disconnect (YY.2.5.1, YY.2.8.1, YY.2.9.1).
type Error struct {
	Class uint32
	Code  uint32
}

func (e *Error) Error() string {
	return fmt.Sprintf("wire: error class %s code %s", errorClassName(e.Class), errorCodeName(e.Code))
}

// BACnetErrorClass values an endpoint may report (Clause 21).
const (
	ClassObject        uint32 = 1
	ClassServices      uint32 = 5
	ClassCommunication uint32 = 7
)

// BACnetErrorCode values an endpoint may report (Clause 21). YY.3.1 requires
// UNKNOWN_OBJECT when the network port cannot be found and
// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED when the requested capture point is not
// supported. YY.2.3.1 requires class SERVICES and
// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED for an unrecognized capture position.
const (
	CodeOther                             uint32 = 0
	CodeInconsistentParameters            uint32 = 7
	CodeUnknownObject                     uint32 = 31
	CodeOptionalFunctionalityNotSupported uint32 = 45
	CodeParameterOutOfRange               uint32 = 80
)

var errorClassNames = map[uint32]string{
	ClassObject:        "OBJECT",
	ClassServices:      "SERVICES",
	ClassCommunication: "COMMUNICATION",
}

var errorCodeNames = map[uint32]string{
	CodeOther:                             "OTHER",
	CodeInconsistentParameters:            "INCONSISTENT_PARAMETERS",
	CodeUnknownObject:                     "UNKNOWN_OBJECT",
	CodeOptionalFunctionalityNotSupported: "OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED",
	CodeParameterOutOfRange:               "PARAMETER_OUT_OF_RANGE",
}

func errorClassName(v uint32) string {
	if n, ok := errorClassNames[v]; ok {
		return n
	}
	return fmt.Sprintf("%d", v)
}

func errorCodeName(v uint32) string {
	if n, ok := errorCodeNames[v]; ok {
		return n
	}
	return fmt.Sprintf("%d", v)
}
