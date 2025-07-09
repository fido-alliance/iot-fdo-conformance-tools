package fdoshared

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

/* ----- VOUCHER ----- */

type OwnershipVoucherHeader struct {
	_                  struct{} `cbor:",toarray"`
	OVHProtVer         ProtVersion
	OVGuid             FdoGuid
	OVRvInfo           RendezvousInfo
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
		return errors.New("OVProtVer is not 101. ")
	}

	if h.OVDevCertChain == nil { // TODO: Future
		return errors.New("EPID not supported")
	}

	if err := h.VerifyOVEntries(); err != nil {
		return errors.New("could not verify OVEntries. " + err.Error())
	}

	ovHeader, err := h.GetOVHeader()
	if err != nil {
		return errors.New(err.Error())
	}

	if ovHeader.OVHProtVer != ProtVer101 {
		return errors.New("OVHProtVer is not 101")
	}

	if len(ovHeader.OVRvInfo) == 0 {
		return errors.New("OVRvInfo is empty")
	}

	if ovHeader.OVDeviceInfo == "" {
		return errors.New("OVDeviceInfo is empty")
	}

	ovDevCertChainCert, err := ComputeOVDevCertChainHash(*h.OVDevCertChain, ovHeader.OVDevCertChainHash.Type)
	if err != nil {
		return errors.New("could not compute OVDevCertChain hash ")
	}

	if !bytes.Equal(ovDevCertChainCert.Hash, ovHeader.OVDevCertChainHash.Hash) {
		return errors.New("could not verify OVDevCertChain hash")
	}

	err = h.VerifyOVEntries()
	if err != nil {
		return errors.New("" + err.Error())
	}

	return nil
}

func (h OwnershipVoucher) GetOVHeader() (OwnershipVoucherHeader, error) {
	var ovHeader OwnershipVoucherHeader
	err := CborCust.Unmarshal(h.OVHeaderTag, &ovHeader)

	if err != nil {
		return OwnershipVoucherHeader{}, errors.New("error decoding OVHeader. " + err.Error())
	}

	return ovHeader, nil
}

func (h OwnershipVoucher) GetFinalOwnerPublicKey() (FdoPublicKey, error) {
	if len(h.OVEntryArray) == 0 {
		return FdoPublicKey{}, errors.New("error OVEntryArray is empty")
	}

	finalOVEntry := h.OVEntryArray[len(h.OVEntryArray)-1]

	var finalOVEntryPayload OVEntryPayload
	err := CborCust.Unmarshal(finalOVEntry.Payload, &finalOVEntryPayload)
	if err != nil {
		return FdoPublicKey{}, errors.New("error decoding last OVEntry payload")
	}

	return finalOVEntryPayload.OVEPubKey, nil
}

func (h CoseSignature) GetOVEntryPubKey() (FdoPublicKey, error) {
	var finalOVEntryPayload OVEntryPayload
	err := CborCust.Unmarshal(h.Payload, &finalOVEntryPayload)
	if err != nil {
		return FdoPublicKey{}, errors.New("error decoding OVEntry payload")
	}

	return finalOVEntryPayload.OVEPubKey, nil
}

type OVEntryArray []CoseSignature

func (h OVEntryArray) VerifyEntries(ovHeaderTag []byte, ovHeaderHMac HashOrHmac) error {
	var lastOVEntry CoseSignature
	var lastOVEntryPublicKey FdoPublicKey

	var voucherHeader OwnershipVoucherHeader
	err := CborCust.Unmarshal(ovHeaderTag, &voucherHeader)
	if err != nil {
		return errors.New("error decoding VoucherHeader: " + err.Error())
	}

	for i, OVEntry := range h {
		var OVEntryPayload OVEntryPayload
		err := CborCust.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			return errors.New("error decoding OVEntry payload: " + err.Error())
		}

		if i == 0 {
			headerHmacBytes, _ := CborCust.Marshal(ovHeaderHMac)
			firstEntryHashContents := append(ovHeaderTag, headerHmacBytes...)
			err := VerifyHash(firstEntryHashContents, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("error verifying OVEntry Hash: " + err.Error())
			}

			err = VerifyCoseSignature(OVEntry, voucherHeader.OVPublicKey)
			if err != nil {
				return errors.New("error verifying OVEntry Signature: " + err.Error())
			}
		} else {
			lastOVEntryBytes, _ := CborCust.Marshal(lastOVEntry)

			err := VerifyHash(lastOVEntryBytes, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("error verifying OVEntry Hash: " + err.Error())
			}

			err = VerifyCoseSignature(OVEntry, lastOVEntryPublicKey)
			if err != nil {
				return errors.New("error verifying OVEntry Signature: " + err.Error())
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
		return nil, errors.New("missing voucher")
	}

	if voucherBlock.Type != OWNERSHIP_VOUCHER_PEM_TYPE {
		return nil, errors.New("error. PEM type is not \"OWNERSHIP VOUCHER\"")
	}

	privateKeyBytes, _ := pem.Decode(rest)
	if privateKeyBytes == nil {
		return nil, errors.New("missing private key")
	}

	// CBOR decode voucher

	var voucherInst OwnershipVoucher
	err := CborCust.Unmarshal(voucherBlock.Bytes, &voucherInst)
	if err != nil {
		return nil, errors.New("failed to CBOR decode voucher")
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

type DeviceCredAndVoucher struct {
	VoucherDBEntry      VoucherDBEntry
	WawDeviceCredential WawDeviceCredential
}

func GeneratePKIXECKeypair(sgType DeviceSgType) (interface{}, *FdoPublicKey, error) {
	var curve elliptic.Curve
	var pkType FdoPkType

	if sgType == StSECP256R1 {
		curve = elliptic.P256()
		pkType = SECP256R1
	} else if sgType == StSECP384R1 {
		curve = elliptic.P384()
		pkType = SECP384R1
	} else {
		return nil, nil, fmt.Errorf("%d is an unsupported SgType", sgType)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.New("error generating new private key. " + err.Error())
	}

	publicKeyPkix, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, errors.New("error marshaling public key. " + err.Error())
	}

	return privateKey, &FdoPublicKey{
		PkType: pkType,
		PkEnc:  X509,
		PkBody: publicKeyPkix,
	}, nil
}

func GeneratePKIXRSAKeypair(sgType DeviceSgType) (interface{}, *FdoPublicKey, error) {
	var pkType FdoPkType
	var rsaKeySize int

	if sgType == StRSA2048 {
		pkType = RSA2048RESTR
		rsaKeySize = 2048
	} else if sgType == StRSA3072 {
		pkType = RSAPKCS
		rsaKeySize = 3072
	} else {
		return nil, nil, fmt.Errorf("%d is an unsupported RSA SgType", sgType)
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, errors.New("error generating new RSA private key. " + err.Error())
	}
	publickey := &privatekey.PublicKey

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, nil, errors.New("error marshaling RSA public key. " + err.Error())
	}

	return privatekey, &FdoPublicKey{
		PkType: pkType,
		PkEnc:  X509,
		PkBody: publicKeyBytes,
	}, nil
}

func GenerateVoucherKeypair(sgType DeviceSgType) (interface{}, *FdoPublicKey, error) {
	switch sgType {
	case StSECP256R1, StSECP384R1:
		return GeneratePKIXECKeypair(sgType)
	case StRSA2048, StRSA3072:
		return GeneratePKIXRSAKeypair(sgType)
	default:
		return nil, nil, fmt.Errorf("%d is an unsupported SgType for the device", sgType)
	}
}

func MarshalPrivateKey(privKey interface{}, sgType DeviceSgType) ([]byte, error) {
	switch sgType {
	case StSECP256R1, StSECP384R1:
		return x509.MarshalPKCS8PrivateKey(privKey.(*ecdsa.PrivateKey))

	case StRSA2048, StRSA3072:
		return x509.MarshalPKCS8PrivateKey(privKey.(*rsa.PrivateKey))

	default:
		return []byte{}, fmt.Errorf("%d is an unsupported SgType", sgType)
	}
}
