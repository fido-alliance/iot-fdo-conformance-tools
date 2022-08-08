package fdoshared

import (
	"bytes"
	"encoding/pem"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const OWNERSHIP_VOUCHER_PEM_TYPE string = "OWNERSHIP VOUCHER"

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
	OVEntryArray   OVEntryArray
}

type OVEntryPayload struct {
	_                struct{} `cbor:",toarray"`
	OVEHashPrevEntry HashOrHmac
	OVEHashHdrInfo   HashOrHmac
	OVEExtra         *[]byte
	OVEPubKey        FdoPublicKey
}

func (h OwnershipVoucher) Validate() error {
	if h.OVProtVer != ProtVer101 {
		return errors.New("error verifying ownershipVoucher. OVProtVer is not 101. ")
	}

	ovHeader, err := h.GetOVHeader()
	if err != nil {
		return errors.New("error verifying ownershipVoucher. " + err.Error())
	}

	ovDevCertChainCert, err := ComputeOVDevCertChainHash(*h.OVDevCertChain, ovHeader.OVDevCertChainHash.Type)
	if err != nil {
		return errors.New("error verifying ownershipVoucher. Could not compute OVDevCertChain hash ")
	}

	if !bytes.Equal(ovDevCertChainCert.Hash, ovHeader.OVDevCertChainHash.Hash) {
		return errors.New("error verifying ownershipVoucher. Could not verify OVDevCertChain hash")
	}

	err = h.VerifyOVEntries()
	if err != nil {
		return errors.New("error verifying ownershipVoucher. " + err.Error())
	}

	return nil
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

func (h CoseSignature) GetOVEntryPubKey() (FdoPublicKey, error) {
	var finalOVEntryPayload OVEntryPayload
	err := cbor.Unmarshal(h.Payload, &finalOVEntryPayload)
	if err != nil {
		return FdoPublicKey{}, errors.New("Error decoding OVEntry payload!")
	}

	return finalOVEntryPayload.OVEPubKey, nil
}

type OVEntryArray []CoseSignature

func (h OVEntryArray) VerifyEntries(ovHeaderTag []byte, ovHeaderHMac HashOrHmac) error {
	var lastOVEntry CoseSignature
	var lastOVEntryPublicKey FdoPublicKey

	var voucherHeader OwnershipVoucherHeader
	err := cbor.Unmarshal(ovHeaderTag, &voucherHeader)
	if err != nil {
		return errors.New("Error decoding VoucherHeader: " + err.Error())
	}

	for i, OVEntry := range h {
		var OVEntryPayload OVEntryPayload
		err := cbor.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			return errors.New("Error decoding OVEntry payload: " + err.Error())
		}

		if i == 0 {
			headerHmacBytes, _ := cbor.Marshal(ovHeaderHMac)
			firstEntryHashContents := append(ovHeaderTag, headerHmacBytes...)
			err := VerifyHash(firstEntryHashContents, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Error verifying OVEntry Hash: " + err.Error())
			}

			err = VerifyCoseSignature(OVEntry, voucherHeader.OVPublicKey)
			if err != nil {
				return errors.New("Error verifying OVEntry Signature: " + err.Error())
			}
		} else {
			lastOVEntryBytes, _ := cbor.Marshal(lastOVEntry)

			err := VerifyHash(lastOVEntryBytes, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Error verifying OVEntry Hash: " + err.Error())
			}

			err = VerifyCoseSignature(OVEntry, lastOVEntryPublicKey)
			if err != nil {
				return errors.New("Error verifying OVEntry Signature: " + err.Error())
			}
		}

		lastOVEntry = OVEntry
		lastOVEntryPublicKey = OVEntryPayload.OVEPubKey
	}
	return nil
}

func (h OwnershipVoucher) VerifyOVEntries() error {
	return h.OVEntryArray.VerifyEntries(h.OVHeaderTag, h.OVHeaderHMac)
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

type VoucherDBEntry struct {
	_              struct{} `cbor:",toarray"`
	Voucher        OwnershipVoucher
	PrivateKeyX509 []byte
}
