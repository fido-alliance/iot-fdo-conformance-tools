package fdoshared

import (
	"errors"
	"log"

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
	OVGuid             FdoGuid
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
	if h.OVProtVer != ProtVer101 {
		log.Println("Error verifying ownershipVoucher protver. ")
		return false, errors.New("error verifying ownershipVoucher protver. ")
	}

	// Decode Voucher Header
	var OVHeaderInst OwnershipVoucherHeader
	err := cbor.Unmarshal(h.OVHeaderTag, &OVHeaderInst)
	if err != nil {
		log.Println("Error verifying ownershipVoucher, couldn't decode OVHeader. ")
		return false, errors.New("error verifying ownershipVoucher, couldn't decode OVHeader ")
	}

	// Verify ProtVersion ??

	// Verify OVDevCertChainHash

	// “OVDevCertChainHash” = Hash of the concatenation of the contents of each byte string in “OwnershipVoucher.OVDevCertChain”,
	//  in the presented order. When OVDevCertChain is CBOR null, OVDevCertChainHash is also CBOR null.

	OVDevCertChain_Certs, err := ComputeOVDevCertChainHash(*h.OVDevCertChain, h.OVHeaderHMac.Type)
	if err != nil {
		log.Println("error verifying ownershipVoucher, couldn't compute bytes for OVDevCertChain. ")
		return false, errors.New("error verifying ownershipVoucher, couldn't compute bytes for OVDevCertChain")
	}

	verifiedHash, err := VerifyHash(OVDevCertChain_Certs.Hash, *OVHeaderInst.OVDevCertChainHash)
	if err != nil || !verifiedHash {
		log.Println("error verifying ownershipVoucher, couldn't verify hash for OVDevCertChain. ")
		return false, errors.New("error verifying ownershipVoucher, couldn't verify hash for OVDevCertChain")
	}

	// Verify OVDevCertChain
	// => The certificates and signature chain of OwnershipVoucher.OVDevCertChain are verified.

	// Verification of the Device Certificate Chain: The Device receiving the Ownership Voucher must verify it against
	// the Device Credential and verify the HMAC in the Ownership Voucher using the secret stored in the device.

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

func (h OwnershipVoucher) VerifyOVEntries() error {
	var lastOVEntry CoseSignature
	for i, OVEntry := range h.OVEntryArray {
		var OVEntryPayload OVEntryPayload
		err := cbor.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			return errors.New("Error Verifying OVEntries" + err.Error())
		}
		if i == 0 {
			headerHmacBytes, _ := cbor.Marshal(h.OVHeaderHMac)
			firstEntryHashContents := append(h.OVHeaderTag, headerHmacBytes...)
			verifiedHash, err := VerifyHash(firstEntryHashContents, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Internal Server Error" + err.Error())
			}
			if !verifiedHash {
				return errors.New("Could not verify hash of entry 0" + err.Error())
			}
		} else {
			lastOVEntryBytes, err := cbor.Marshal(lastOVEntry)
			if err != nil {
				return errors.New("Error Verifying OVEntries" + err.Error())
			}
			verifiedHash, err := VerifyHash(lastOVEntryBytes, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Internal Server Error" + err.Error())
			}
			if !verifiedHash {
				return errors.New("Could not verify hash (Entry)" + err.Error())
			}
		}
		lastOVEntry = OVEntry
	}
	return nil
}

func ValidateVoucherStructFromCert(voucherFileBytes []byte) (*OwnershipVoucher, error) {
	voucherBlock, rest := pem.Decode(voucherFileBytes)
	if voucherBlock == nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	if voucherBlock.Type != OWNERSHIP_VOUCHER_PEM_TYPE {
		return nil, errors.New("Detected bytes != actual length")
	}

	privateKeyBytes, _ := pem.Decode(rest)
	if privateKeyBytes == nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	// CBOR decode voucher

	var voucherInst OwnershipVoucher
	err := cbor.Unmarshal(voucherBlock.Bytes, &voucherInst)
	if err != nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	return &voucherInst, nil
}

func ComputeOVDevCertChainHash(certs []X509CertificateBytes, hashType HashType) (HashOrHmac, error) {
	var totalBytes []byte
	for _, cert := range certs {
		totalBytes = append(totalBytes, cert...)
	}

	return GenerateFdoHash(totalBytes, hashType)
}
