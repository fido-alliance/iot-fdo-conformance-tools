package fdoshared

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
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

func (h FdoGuid) GetFormatted() string {
	uuidBytes := h[:]
	uuidInst, _ := uuid.FromBytes(uuidBytes)

	return uuidInst.String()
}

func (h FdoGuid) GetFormattedHex() string {
	uuidBytes := h[:]
	uuidInst, _ := uuid.FromBytes(uuidBytes)

	return strings.ReplaceAll(uuidInst.String(), "-", "")
}

func (h FdoGuid) Equals(secondGuid FdoGuid) bool {
	return bytes.Equal(h[:], secondGuid[:])
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

type FdoGuidList []FdoGuid

func (h FdoGuidList) GetRandomBatch(size int) FdoGuidList {
	listLen := len(h)

	if listLen == 0 {
		return FdoGuidList{}
	}

	randomLoc := NewRandomInt(0, listLen-1)

	if randomLoc+size > listLen {
		l1len := listLen - randomLoc
		l1 := h[randomLoc : randomLoc+l1len-1]
		l2 := h[0 : size-len(l1)]

		return append(l1, l2...)
	}

	return h[randomLoc : randomLoc+size]
}

func (h FdoGuidList) Contains(guid FdoGuid) bool {
	for _, arrGuid := range h {
		if arrGuid.Equals(guid) {
			return true
		}
	}

	return false
}

func (h FdoGuidList) GetRandomSelection(size int) FdoGuidList {
	randomPick := FdoGuidList{}

	if size >= len(h) {
		return h
	}

	for {
		randomId := NewRandomInt(0, len(h)-1)
		randomGuid := h[randomId]

		if !randomPick.Contains(randomGuid) {
			randomPick = append(randomPick, randomGuid)
		}

		if len(randomPick) >= size {
			break
		}
	}

	return randomPick
}

type FdoSeedIDs map[DeviceSgType]FdoGuidList

func (h *FdoSeedIDs) GetTestBatch(size int) FdoSeedIDs {
	var newTestBatch FdoSeedIDs = FdoSeedIDs{}

	for k, v := range *h {
		newTestBatch[k] = v.GetRandomBatch(size)
	}

	return newTestBatch
}

func (h *FdoSeedIDs) GetRandomTestGuid() FdoGuid {
	var randomGuids []FdoGuid = []FdoGuid{}

	for _, v := range *h {
		if len(v) == 0 {
			continue
		}

		randLoc := NewRandomInt(0, len(v)-1)
		randomGuids = append(randomGuids, v[randLoc])
	}

	randLoc := NewRandomInt(0, len(randomGuids)-1)
	return randomGuids[randLoc]
}

func (h *FdoSeedIDs) GetRandomTestGuidForSgType(sgType DeviceSgType) FdoGuid {
	sh := *h
	var randomGuids []FdoGuid = sh[sgType]

	randLoc := NewRandomInt(0, len(randomGuids)-1)
	return randomGuids[randLoc]
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

func NewRandomInt(min int, max int) int {
	if min == max {
		return min
	}

	maxBint := new(big.Int).SetInt64(int64(max - min))
	newRandBint, _ := rand.Int(rand.Reader, maxBint)
	return min + int(newRandBint.Int64())
}

func ByteIdsContain(byteIds [][]byte, byteId []byte) bool {
	for _, arrItem := range byteIds {
		if bytes.Equal(arrItem, byteId) {
			return true
		}
	}

	return false
}

func StringsContain(stringsArr []string, item string) bool {
	for _, str := range stringsArr {
		if str == item {
			return true
		}
	}

	return false
}
