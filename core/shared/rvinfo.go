package fdoshared

import (
	"errors"
	"fmt"
	"log"
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

type RendezvousInstrList []RendezvousInstr

// Mapped RV Instructions to struct

func GetMappedRVInstructions(instrLists []RendezvousInstrList) (MappedRVInstructions, error) {
	return NewMappedRVInstructions(instrLists)
}

type MappedRVInstructions []RendezvousInstructionBlock

func (h *MappedRVInstructions) GetOwnerOnly() MappedRVInstructions {
	var result MappedRVInstructions
	for _, instr := range *h {
		if instr.RVOwnerOnly || !instr.RVDevOnly {
			result = append(result, instr)
		}
	}

	return result
}

func (h *MappedRVInstructions) GetDevOnly() MappedRVInstructions {
	var result MappedRVInstructions
	for _, instr := range *h {
		if instr.RVDevOnly || !instr.RVOwnerOnly {
			result = append(result, instr)
		}
	}

	return result
}

func NewMappedRVInstructions(instrLists []RendezvousInstrList) (MappedRVInstructions, error) {
	var result MappedRVInstructions

	for _, instrList := range instrLists {
		instrBlock, err := NewRendezvousInstructionBlock(instrList)
		if err != nil {
			return result, err
		}

		result = append(result, instrBlock)
	}

	return result, nil
}

type RendezvousInstructionBlock struct {
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

func (h *RendezvousInstructionBlock) Validate() error {
	if len(h.RVIPAddresses) == 0 && h.RVDns == nil {
		return errors.New("RVIPAddress and RVDns are both nil")
	}

	if h.RVOwnerOnly && h.RVDevOnly {
		return errors.New("RVOwnerOnly and RVDevOnly are both true")
	}

	return nil
}

func (h *RendezvousInstructionBlock) GetOwnerUrls() []string {
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

func NewRendezvousInstructionBlock(instrList RendezvousInstrList) (RendezvousInstructionBlock, error) {
	rvib := RendezvousInstructionBlock{}

	recordedKeys := map[RVVariable]int{}
	for _, instr := range instrList {
		if instr.Key != RVIPAddress && recordedKeys[instr.Key] > 0 {
			return rvib, errors.New("duplicate key in RendezvousInstrList")
		}

		switch instr.Key {
		case RVDevOnly:
			rvib.RVDevOnly = true
		case RVOwnerOnly:
			rvib.RVOwnerOnly = true
		case RVIPAddress:
			log.Println("RVIPAddress", instr.Value)
			ipv4addr, err := FdoIPAddressFromBytes(instr.Value)
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

		recordedKeys[instr.Key]++
	}

	err := rvib.Validate()

	return rvib, err
}
