package fdoshared

import (
	"errors"
	"log"

	"github.com/fxamacker/cbor/v2"
)

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

	OVDevCertChain_Certs, err := ComputeOVDevCertChainHash(*h.OVDevCertChain, -16)

	verifiedHash, err := VerifyHash(OVDevCertChain_Certs, *OVHeaderInst.OVDevCertChainHash)
	if err != nil {
		log.Println("error verifying ownershipVoucher, couldn't verify hash for OVDevCertChain. ")
		return false, errors.New("error verifying ownershipVoucher, couldn't verify hash for OVDevCertChain")
	}
	if verifiedHash == false {

	}

	// Verify OVDevCertChain
	//

	// Verification of the Device Certificate Chain: The Device receiving the Ownership Voucher must verify it against the Device Credential and verify the HMAC in the Ownership Voucher using the secret stored in the device.

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
