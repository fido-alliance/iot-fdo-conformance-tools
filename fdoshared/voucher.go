package fdoshared

import (
	"errors"

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
