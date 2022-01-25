package fdoshared

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
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

type RVProtocolValue uint

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
	Value *[]byte
}

type RendezvousInstrList []RendezvousInstr

type RendezvousInstructionBlock struct {
	RVDevOnly    bool
	RVOwnerOnly  bool
	RVIPAddress  FdoIPAddress
	RVDevPort    string
	RVOwnerPort  uint16
	RVDns        uint16
	RVSvCertHash HashOrHmac
	RVClCertHash HashOrHmac
	RVUserInput  bool
	RVWifiSsid   string
	RVWifiPw     string
	RVMedium     RVMediumValue
	RVProtocol   RVProtocolValue
	RVDelaysec   uint32
	RVBypass     bool
	RVExtRV      []interface{}
}

/* ----- VOUCHER ----- */

type OwnershipVoucherHeader struct {
	_                  struct{} `cbor:",toarray"`
	OVHProtVer         ProtVersion
	OVGuid             FDOGuid
	OVRvInfo           interface{}
	OVDeviceInfo       string
	OVPublicKey        FdoPublicKey
	OVDevCertChainHash *HashOrHmac
}

type OwnershipVoucher struct {
	_              struct{} `cbor:",toarray"`
	OVProtVer      ProtVersion
	OVHeaderTag    []byte
	OVHeaderHMac   HashOrHmac
	OVDevCertChain *[]X509CertificateBytes
	OVEntryArray   []CoseSignature
}

type OVEntryPayload struct {
	_                struct{} `cbor:",toarray"`
	OVEHashPrevEntry HashOrHmac
	OVEHashHdrInfo   HashOrHmac
	OVEExtra         *[]byte
	OVEPubKey        FdoPublicKey
}

func (h OwnershipVoucher) Validate() (bool, error) {
	// TODO

	// Verify ProtVersion

	// Decode Voucher Header

	// Verify ProtVersion

	// Verify OVDevCertChainHash

	// Verify OVDevCertChain

	// Verify OVEntryArray

	return true, nil
}

func (h OwnershipVoucher) GetOVHeader() (OwnershipVoucherHeader, error) {
	var ovHeader OwnershipVoucherHeader
	err := cbor.Unmarshal(h.OVHeaderTag, &ovHeader)

	if err != nil {
		return OwnershipVoucherHeader{}, errors.New("Error decoding OVHeader. " + err.Error())
	}

	return ovHeader, nil
}

func (h OwnershipVoucher) GetFinalOwnerPublicKey() (FdoPublicKey, error) {
	finalOVEntry := h.OVEntryArray[len(h.OVEntryArray)-1]

	var finalOVEntryPayload OVEntryPayload
	err := cbor.Unmarshal(finalOVEntry.Payload, &finalOVEntryPayload)
	if err != nil {
		return FdoPublicKey{}, errors.New("Error decoding last OVEntry payload!")
	}

	return finalOVEntryPayload.OVEPubKey, nil
}
