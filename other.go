package fdoshared

import (
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type ProtVersion uint16

const (
	ProtVer100 ProtVersion = 100
	ProtVer101 ProtVersion = 101
)

type FdoGuid [16]byte

func (h *FdoGuid) GetFormatted() string {
	uuidBytes := h[:]
	uuidInst, _ := uuid.ParseBytes(uuidBytes)

	return uuidInst.String()
}

func (h *FdoGuid) GetFormattedHex() string {
	uuidBytes := h[:]
	uuidInst, _ := uuid.ParseBytes(uuidBytes)

	return strings.ReplaceAll(uuidInst.String(), "-", "")
}

func NewFdoGuid() FdoGuid {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()
	var newFdoGuid FdoGuid
	copy(newFdoGuid[:], uuidBytes)

	return newFdoGuid
}

func NewFdoGuid_FIDO() FdoGuid {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()
	var newFdoGuid FdoGuid
	copy(newFdoGuid[:], uuidBytes)

	newFdoGuid[0] = 0xF1
	newFdoGuid[1] = 0xD0
	newFdoGuid[2] = 0xFD
	newFdoGuid[3] = 0x00

	return newFdoGuid
}

// timestamp = null / UTCStr / UTCInt / TIME_T
// UTCStr = #6.0(tstr)
// UTCInt = #6.1(uint)
// TIMET  = #6.1(uint)
type FdoTimestamp interface{} // TODO

const IPv6Len = 16
const IPv4Len = 4

type FdoIPAddress []byte

func (h FdoIPAddress) IsValid() bool {
	if len(h) != IPv4Len && len(h) != IPv6Len {
		return false
	}

	return true
}

func (h FdoIPAddress) ToString() string {
	// TODO
	return ""
}

type TransportProtocol uint16

const (
	ProtTCP   TransportProtocol = 1
	ProtTLS   TransportProtocol = 2
	ProtHTTP  TransportProtocol = 3
	ProtCoAP  TransportProtocol = 4
	ProtHTTPS TransportProtocol = 5
	ProtCoAPS TransportProtocol = 6
)

type RVTO2AddrEntry struct {
	_ struct{} `cbor:",toarray"`

	RVIP       *FdoIPAddress
	RVDNS      *string
	RVPort     uint16
	RVProtocol TransportProtocol
}

func DecodeErrorResponse(bodyBytes []byte) (*FdoError, error) {
	var errInst FdoError
	err := cbor.Unmarshal(bodyBytes, &errInst)
	if err != nil {
		return nil, errors.New("Error decoding FdoError " + err.Error())
	}

	return &errInst, nil
}
