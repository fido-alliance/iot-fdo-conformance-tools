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
	Value []byte
}

func NewRendezvousInstr(key RVVariable, val interface{}) RendezvousInstr {
	valBytes, _ := cbor.Marshal(val)

	return RendezvousInstr{
		Key:   key,
		Value: valBytes,
	}
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
		return errors.New("OVProtVer is not 101. ")
	}

	ovHeader, err := h.GetOVHeader()
	if err != nil {
		return errors.New(err.Error())
	}

	if h.OVDevCertChain == nil { // TODO: Future
		return errors.New("EPID not supported")
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
	err := cbor.Unmarshal(h.OVHeaderTag, &ovHeader)

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
	err := cbor.Unmarshal(finalOVEntry.Payload, &finalOVEntryPayload)
	if err != nil {
		return FdoPublicKey{}, errors.New("error decoding last OVEntry payload")
	}

	return finalOVEntryPayload.OVEPubKey, nil
}

func (h CoseSignature) GetOVEntryPubKey() (FdoPublicKey, error) {
	var finalOVEntryPayload OVEntryPayload
	err := cbor.Unmarshal(h.Payload, &finalOVEntryPayload)
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
	err := cbor.Unmarshal(ovHeaderTag, &voucherHeader)
	if err != nil {
		return errors.New("error decoding VoucherHeader: " + err.Error())
	}

	for i, OVEntry := range h {
		var OVEntryPayload OVEntryPayload
		err := cbor.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			return errors.New("error decoding OVEntry payload: " + err.Error())
		}

		if i == 0 {
			headerHmacBytes, _ := cbor.Marshal(ovHeaderHMac)
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
			lastOVEntryBytes, _ := cbor.Marshal(lastOVEntry)

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
	err := cbor.Unmarshal(voucherBlock.Bytes, &voucherInst)
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
	var pkType FdoPkType = RSAPKCS
	var rsaKeySize int

	if sgType == StRSA2048 {
		rsaKeySize = 2048
	} else if sgType == StRSA3072 {
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
		return nil, nil, fmt.Errorf("%d is an unsupported SgType", sgType)
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
