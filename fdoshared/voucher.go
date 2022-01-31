package fdoshared

import (
	"bytes"
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
	OVDevCertChain *[][]X509CertificateBytes
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
	if h.OVProtVer != ProtVer100 && h.OVProtVer != ProtVer101 {
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
	var concatenatedOVDevCertChain []byte
	var OVDevCertChain_Certs []byte
	var cert []X509CertificateBytes
	for i, bstrCert := range h.OVDevCertChain { // iterated will return  bstr[cert1] : e.g., X5CHAIN = [ bstr[cert1] ... bstr[certN] ],
		err = cbor.Unmarshal(bstrCert, &cert) // bstr[cert_n] => cert_n
		if err != nil {
			log.Println("Error verifying ownershipVoucher, couldn't decode entry in OVDevCertChain")
			return false, errors.New("error verifying ownershipVoucher, couldn't decode entry in OVDevCertChain ")
		}
		OVDevCertChain_Certs = append(OVDevCertChain_Certs, cert) // push cert to OVDevCertChain_Certs
	}
	concatenatedOVDevCertChain = OVDevCertChain_Certs.join()

	// concatenatedOVDevCertChain = append(OVDevCertChain_Certs)
	// [JS] const OVDevCertChain_Certs = ['Fire', 'Air', 'Water']; (OVDevCertChain_Certs.join('')) => "FireAirWater"
	calculatedHash, err := GenerateFdoHash(h.concatenatedOVDevCertChain, -16)
	if err != nil {
		log.Println("error verifying ownershipVoucher, couldn't calculate hash for OVDevCertChain. ")
		return false, errors.New("error verifying ownershipVoucher, couldn't calculate hash for OVDevCertChain")
	}
	if bytes.Compare(OVHeaderInst.OVDevCertChainHash, calculatedHash.HashOrHmac[:]) != 0 {

	}
	// So I need to decode every entry in OVDevCertChain, concatenate them together in a var, then hash that var = OVDevCertChainHash

	// “OVDevCertChainHash” = Hash of the concatenation of the contents of each byte string in “OwnershipVoucher.OVDevCertChain”,
	//  in the presented order. When OVDevCertChain is CBOR null, OVDevCertChainHash is also CBOR null.

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
