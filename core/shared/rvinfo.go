package fdoshared

import (
	"errors"
	"fmt"
)

type RVMediumValue uint8

const (
	RVMedEth0    RVMediumValue = 0
	RVMedEth1    RVMediumValue = 1
	RVMedEth2    RVMediumValue = 2
	RVMedEth3    RVMediumValue = 3
	RVMedEth4    RVMediumValue = 4
	RVMedEth5    RVMediumValue = 5
	RVMedEth6    RVMediumValue = 6
	RVMedEth7    RVMediumValue = 7
	RVMedEth8    RVMediumValue = 8
	RVMedEth9    RVMediumValue = 9
	RVMedEthAll  RVMediumValue = 20
	RVMedWifi0   RVMediumValue = 10
	RVMedWifi1   RVMediumValue = 11
	RVMedWifi2   RVMediumValue = 12
	RVMedWifi3   RVMediumValue = 13
	RVMedWifi4   RVMediumValue = 14
	RVMedWifi5   RVMediumValue = 15
	RVMedWifi6   RVMediumValue = 16
	RVMedWifi7   RVMediumValue = 17
	RVMedWifi8   RVMediumValue = 18
	RVMedWifi9   RVMediumValue = 19
	RVMedWifiAll RVMediumValue = 21
)

type RVProtocolValue uint8

const (
	RVProtRest    RVProtocolValue = 0
	RVProtHttp    RVProtocolValue = 1
	RVProtHttps   RVProtocolValue = 2
	RVProtTcp     RVProtocolValue = 3
	RVProtTls     RVProtocolValue = 4
	RVProtCoapTcp RVProtocolValue = 5
	RVProtCoapUdp RVProtocolValue = 6
)

type RVVariable uint8

const (
	RVDevOnly    RVVariable = 0
	RVOwnerOnly  RVVariable = 1
	RVIPAddress  RVVariable = 2
	RVDevPort    RVVariable = 3
	RVOwnerPort  RVVariable = 4
	RVDns        RVVariable = 5
	RVSvCertHash RVVariable = 6
	RVClCertHash RVVariable = 7
	RVUserInput  RVVariable = 8
	RVWifiSsid   RVVariable = 9
	RVWifiPw     RVVariable = 10
	RVMedium     RVVariable = 11
	RVProtocol   RVVariable = 12
	RVDelaysec   RVVariable = 13
	RVBypass     RVVariable = 14
	RVExtRV      RVVariable = 15
)

var RVVariableBoolean []RVVariable = []RVVariable{RVDevOnly, RVOwnerOnly, RVUserInput, RVBypass}

func (h RVVariable) IsBoolean() bool {
	for _, val := range RVVariableBoolean {
		if h == val {
			return true
		}
	}

	return false
}

type RendezvousInstr struct {
	_     struct{} `cbor:",toarray"`
	Key   RVVariable
	Value []byte
}

func NewRendezvousInstr(key RVVariable, val interface{}) RendezvousInstr {
	valBytes, _ := CborCust.Marshal(val)

	return RendezvousInstr{
		Key:   key,
		Value: valBytes,
	}
}

type RendezvousDirective []RendezvousInstr

func (h *RendezvousDirective) AddInstr(instr RendezvousInstr) {
	*h = append(*h, instr)
}

func (h *RendezvousDirective) AddInstrs(instrs []RendezvousInstr) {
	*h = append(*h, instrs...)
}

func (h *RendezvousDirective) Validate() error {
	recordedKeys := map[RVVariable]int{}
	for _, instr := range *h {
		if instr.Key != RVIPAddress && recordedKeys[instr.Key] > 0 {
			return fmt.Errorf("duplicate key (%d) in RendezvousInstrList", instr.Key)
		}

		if instr.Key.IsBoolean() && instr.Value != nil {
			return fmt.Errorf("boolean key (%d) has non-nil value", instr.Key)
		}

		// Is valid cbor
		var v interface{}
		err := CborCust.Unmarshal(instr.Value, &v)
		if err != nil {
			return fmt.Errorf("error decoding RVInstr (%d) value. %s", instr.Key, err.Error())
		}

		recordedKeys[instr.Key]++
	}

	return nil
}

type RendezvousInfo []RendezvousDirective

// Mapped RV Instructions to struct

func GetMappedRVInfo(instrLists RendezvousInfo) (MappedRVInfo, error) {
	return NewMappedRVInfo(instrLists)
}

type MappedRVInfo []MappedRVDirective

func (h *MappedRVInfo) GetOwnerOnly() MappedRVInfo {
	var result MappedRVInfo
	for _, instr := range *h {
		if instr.RVOwnerOnly || !instr.RVDevOnly {
			result = append(result, instr)
		}
	}

	return result
}

func (h *MappedRVInfo) GetDevOnly() MappedRVInfo {
	var result MappedRVInfo
	for _, instr := range *h {
		if instr.RVDevOnly || !instr.RVOwnerOnly {
			result = append(result, instr)
		}
	}

	return result
}

func NewMappedRVInfo(instrLists RendezvousInfo) (MappedRVInfo, error) {
	var result MappedRVInfo

	for _, instrList := range instrLists {
		instrBlock, err := NewMappedRVDirective(instrList)
		if err != nil {
			return result, err
		}

		result = append(result, instrBlock)
	}

	return result, nil
}

type MappedRVDirective struct {
	RVOwnerOnly   bool
	RVDevOnly     bool
	RVIPAddresses []FdoIPAddress
	RVDevPort     *uint16
	RVOwnerPort   *uint16
	RVDns         *string
	RVSvCertHash  *HashOrHmac
	RVClCertHash  *HashOrHmac
	RVUserInput   bool
	RVWifiSsid    *string
	RVWifiPw      *string
	RVMedium      *RVMediumValue
	RVProtocol    *RVProtocolValue
	RVDelaysec    *uint32 // TODO
	RVBypass      bool
	RVExtRV       *[]interface{}
}

func (h *MappedRVDirective) Validate() error {
	if len(h.RVIPAddresses) == 0 && h.RVDns == nil {
		return errors.New("RVIPAddress and RVDns are both nil")
	}

	if h.RVOwnerOnly && h.RVDevOnly {
		return errors.New("RVOwnerOnly and RVDevOnly are both true")
	}

	return nil
}

func (h *MappedRVDirective) GetOwnerUrls() []string {
	var result []string

	selectedPort := uint16(443)

	if h.RVOwnerPort != nil {
		selectedPort = *h.RVOwnerPort
	}

	if h.RVDns != nil {
		result = append(result, fmt.Sprintf("https://%s:%d", *h.RVDns, selectedPort))
	}

	for _, ipAddr := range h.RVIPAddresses {
		result = append(result, fmt.Sprintf("https://%s:%d", ipAddr.String(), selectedPort))
	}

	return result
}

func NewMappedRVDirective(instrList RendezvousDirective) (MappedRVDirective, error) {
	rvib := MappedRVDirective{}

	// Validating the RendezvousDirective
	err := instrList.Validate()
	if err != nil {
		return rvib, err
	}

	for _, instr := range instrList {
		switch instr.Key {
		case RVDevOnly:
			rvib.RVDevOnly = true
		case RVOwnerOnly:
			rvib.RVOwnerOnly = true
		case RVIPAddress:
			var ipAddressBytes []byte
			CborCust.Unmarshal(instr.Value, &ipAddressBytes)

			ipv4addr, err := FdoIPAddressFromBytes(ipAddressBytes)
			if err != nil {
				return rvib, err
			}

			rvib.RVIPAddresses = append(rvib.RVIPAddresses, ipv4addr)
		case RVDevPort:
			rvib.RVDevPort = new(uint16)
			CborCust.Unmarshal(instr.Value, rvib.RVDevPort)
		case RVOwnerPort:
			rvib.RVOwnerPort = new(uint16)
			CborCust.Unmarshal(instr.Value, rvib.RVOwnerPort)
		case RVDns:
			rvib.RVDns = new(string)
			CborCust.Unmarshal(instr.Value, rvib.RVDns)
		case RVSvCertHash:
			rvib.RVSvCertHash = new(HashOrHmac)
			CborCust.Unmarshal(instr.Value, rvib.RVSvCertHash)
		case RVClCertHash:
			rvib.RVClCertHash = new(HashOrHmac)
			CborCust.Unmarshal(instr.Value, rvib.RVClCertHash)
		case RVUserInput:
			rvib.RVUserInput = true
		case RVWifiSsid:
			rvib.RVWifiSsid = new(string)
			CborCust.Unmarshal(instr.Value, rvib.RVWifiSsid)
		case RVWifiPw:
			rvib.RVWifiPw = new(string)
			CborCust.Unmarshal(instr.Value, rvib.RVWifiPw)
		case RVMedium:
			rvib.RVMedium = new(RVMediumValue)
			CborCust.Unmarshal(instr.Value, rvib.RVMedium)
		case RVProtocol:
			rvib.RVProtocol = new(RVProtocolValue)
			CborCust.Unmarshal(instr.Value, rvib.RVProtocol)
		case RVDelaysec:
			rvib.RVDelaysec = new(uint32)
			CborCust.Unmarshal(instr.Value, rvib.RVDelaysec)
		case RVBypass:
			rvib.RVBypass = true
		case RVExtRV:
			rvib.RVExtRV = new([]interface{})
			CborCust.Unmarshal(instr.Value, rvib.RVExtRV)

		}
	}

	// Validating the result MappedRVDirective
	err = rvib.Validate()

	return rvib, err
}
