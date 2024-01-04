package fdoshared

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"

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

func (h *FdoGuid) FromBytes(guidBytes []byte) error {
	if len(guidBytes) != 16 {
		return errors.New("Invalid GUID byte length")
	}

	copy(h[:], guidBytes)
	return nil
}

func NewFdoGuid() FdoGuid {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()
	var newFdoGuid FdoGuid
	copy(newFdoGuid[:], uuidBytes)

	return newFdoGuid
}

/* Generates FIDO Alliance FDO prefixed GUID */
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

const IP6Len = 16
const IP4Len = 4

type FdoIPAddress []byte

func (h FdoIPAddress) IsValid() bool {
	if len(h) != IP4Len && len(h) != IP6Len {
		return false
	}

	return true
}

func (h *FdoIPAddress) String() string {
	return net.IP(*h).String()
}

func FdoIPAddressFromString(ipStr string) (FdoIPAddress, error) {
	parsedIPAddress := net.ParseIP(ipStr)
	if parsedIPAddress == nil {
		return nil, errors.New("invalid IP string")
	}

	if parsedIPAddress.To4() != nil {
		return FdoIPAddressFromBytes(parsedIPAddress.To4())
	} else if parsedIPAddress.To16() != nil {
		return FdoIPAddressFromBytes(parsedIPAddress.To16())
	}

	return nil, errors.New("invalid IP string")
}

func FdoIPAddressFromBytes(ipvBytes []byte) (FdoIPAddress, error) {
	if len(ipvBytes) != IP4Len && len(ipvBytes) != IP6Len {
		return nil, errors.New("invalid IP byte length. Must be IP4(4) or IP6(16) bytes")
	}

	return FdoIPAddress(ipvBytes), nil
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

var TProtToRVProt = map[TransportProtocol]RVProtocolValue{
	ProtTCP:   RVProtTcp,
	ProtTLS:   RVProtTls,
	ProtHTTP:  RVProtHttp,
	ProtHTTPS: RVProtHttps,
}

type RVTO2AddrEntry struct {
	_ struct{} `cbor:",toarray"`

	RVIP       *FdoIPAddress
	RVDNS      *string
	RVPort     uint16
	RVProtocol TransportProtocol
}

func DecodeErrorResponse(bodyBytes []byte) (*FdoError, error) {
	var errInst FdoError
	err := CborCust.Unmarshal(bodyBytes, &errInst)
	if err != nil {
		return nil, errors.New("error decoding FdoError " + err.Error())
	}

	return &errInst, nil
}

func TryCborUnmarshal(bodyBytes []byte, target interface{}) (*FdoError, error) {
	err := CborCust.Unmarshal(bodyBytes, target)
	if err != nil {
		return DecodeErrorResponse(bodyBytes)
	}

	return nil, nil
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

func UrlToTOAddrEntry(inurl string) (*RVTO2AddrEntry, error) {
	var result RVTO2AddrEntry = RVTO2AddrEntry{}

	// Base checks
	u, err := url.Parse(inurl)
	if err != nil {
		return nil, fmt.Errorf("error parsing url %s. %s", inurl, err.Error())
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme %s", u.Scheme)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid url hostname %s", u.Hostname())
	}

	// FDO parsing
	var tProt TransportProtocol = ProtHTTP
	var selectedPort uint16 = 80
	if u.Scheme == "https" {
		tProt = ProtHTTPS
		selectedPort = 443
	}

	if u.Port() != "" {
		parsedPort, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid url port %s", u.Port())
		}

		selectedPort = uint16(parsedPort)
	}

	// Parsing IP Address or Host
	isIp := false
	fdoIpAddress := FdoIPAddress{}
	parsedIPAddress := net.ParseIP(u.Hostname())
	if parsedIPAddress != nil {
		fdoipTemp, err := FdoIPAddressFromString(u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("invalid ip %s", u.Hostname())
		}

		isIp = true
		fdoIpAddress = fdoipTemp
	}

	result.RVProtocol = tProt
	result.RVPort = selectedPort

	if isIp {
		result.RVIP = &fdoIpAddress
	} else {
		hostName := u.Hostname()
		result.RVDNS = &hostName
	}

	return &result, nil
}

func UrlToRvDirective(inurl string) (RendezvousDirective, error) {
	rvto2addr, err := UrlToTOAddrEntry(inurl)
	if err != nil {
		return nil, err
	}

	scheme, ok := TProtToRVProt[rvto2addr.RVProtocol]
	if !ok {
		return nil, fmt.Errorf("invalid protocol %d", rvto2addr.RVProtocol)
	}

	var rvDirective = RendezvousDirective{
		NewRendezvousInstr(RVProtocol, scheme),
		NewRendezvousInstr(RVDevPort, rvto2addr.RVPort),
		NewRendezvousInstr(RVOwnerPort, rvto2addr.RVPort), // TODO: Future
	}

	if rvto2addr.RVDNS == nil {
		rvDirective = append(rvDirective, NewRendezvousInstr(RVIPAddress, rvto2addr.RVIP))
	} else {
		rvDirective = append(rvDirective, NewRendezvousInstr(RVDns, rvto2addr.RVDNS))
	}

	return rvDirective, nil
}

func UrlsToRendezvousInfo(urls []string) (RendezvousInfo, error) {
	var rvInfo = RendezvousInfo{}

	for _, url := range urls {
		rvDirective, err := UrlToRvDirective(url)
		if err != nil {
			return nil, err
		}

		rvInfo = append(rvInfo, rvDirective)
	}

	return rvInfo, nil
}

func GenerateEatGuid(fdoGuid FdoGuid) [17]byte {
	var result [17]byte
	copy(result[:], append([]byte{0x01}, fdoGuid[:]...))

	return result
}
