package fdoshared

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type UnprotectedHeader struct {
	CUPHNonce       FdoNonce     `cbor:"256,keyasint,omitempty"`
	CUPHOwnerPubKey FdoPublicKey `cbor:"257,keyasint,omitempty"`
	EATMAROEPrefix  []byte       `cbor:"-258,keyasint,omitempty"`
	EUPHNonce       FdoNonce     `cbor:"-259,keyasint,omitempty"`
	AESIV           []byte       `cbor:"5,keyasint,omitempty"`
}

type ProtectedHeader struct {
	Alg       int    `cbor:"1,keyasint,omitempty"`
	Kid       []byte `cbor:"4,keyasint,omitempty"`
	IV        []byte `cbor:"5,keyasint,omitempty"`
	PartialIV []byte `cbor:"6,keyasint,omitempty"`
}

type CoseSignature struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected UnprotectedHeader
	Payload     []byte
	Signature   []byte
}

type EATPayloadBase struct {
	// EatFDO   []byte   `cbor:"-257,keyasint,omitempty"` // TODO change TYPE??
	// EatFDO   `cbor:"-257,keyasint,omitempty"` // TODO change TYPE??
	EatNonce FdoNonce              `cbor:"10,keyasint,omitempty"`
	EatUEID  [17]byte              `cbor:"11,keyasint,omitempty"`
	EatFDO   TO2ProveDevicePayload `cbor:"-257,keyasint,omitempty"`
}

type TO2ProveDevicePayload struct {
	XBKeyExchange []byte
}

type CoseContext string

const Signature1 CoseContext = "Signature1"

// Signature must be computed over a sig_structure:
// Sig_structure = [
//   context : "Signature" / "Signature1" / "CounterSignature",
//   body_protected : empty_or_serialized_map,
//   external_aad : bstr,
//   payload : bstr
// ]
//
// See the COSE RFC 8152 for details on this.

type CoseSignatureStructure struct {
	_           struct{} `cbor:",toarray"`
	Context     CoseContext
	Protected   []byte // Protected header. Serialized
	ExternalAAD []byte // External authentication data. For FDO keep it zero length byte string
	Payload     []byte
}

func NewSig1Payload(protectedHeader []byte, payload []byte) ([]byte, error) {
	sig1Inst := CoseSignatureStructure{
		Context:     Signature1,
		Protected:   protectedHeader,
		ExternalAAD: []byte{},
		Payload:     payload,
	}

	sig1Bytes, err := cbor.Marshal(sig1Inst)
	if err != nil {
		return []byte{}, errors.New("Error marshaling cose signature structure for Sig1. " + err.Error())
	}

	return sig1Bytes, nil
}

type FdoPkType uint8

const (
	RSA2048RESTR FdoPkType = 1  // RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
	RSAPKCS      FdoPkType = 5  // RSA key, PKCS1, v1.5
	RSAPSS       FdoPkType = 6  // RSA key, PSS
	SECP256R1    FdoPkType = 10 // ECDSA secp256r1 = NIST-P-256 = prime256v1
	SECP384R1    FdoPkType = 11 // ECDSA secp384r1 = NIST-P-384
)

var FdoPkType_List []FdoPkType = []FdoPkType{
	RSA2048RESTR,
	RSAPKCS,
	RSAPSS,
	SECP256R1,
	SECP384R1,
}

const (
	SECP256R1_SIG_LEN int = 64
	SECP384R1_SIG_LEN int = 96
)

type FdoPkEnc uint8

const (
	Crypto  FdoPkEnc = 0 // TODO: EPID
	X509    FdoPkEnc = 1
	X5CHAIN FdoPkEnc = 2
	COSEKEY FdoPkEnc = 3
)

var FdoPkEnc_List []FdoPkEnc = []FdoPkEnc{
	// Crypto, // TODO: EPID
	X509,
	X5CHAIN,
	COSEKEY,
}

type FdoPublicKey struct {
	_      struct{} `cbor:",toarray"`
	PkType FdoPkType
	PkEnc  FdoPkEnc
	PkBody interface{}
}

func (h FdoPublicKey) Equal(bKey FdoPublicKey) error {
	aBytes, err := cbor.Marshal(h)
	if err != nil {
		return errors.New("error comparing FDO public keys. Can not CBOR marshal pubKeyA")
	}

	bBytes, err := cbor.Marshal(bKey)
	if err != nil {
		return errors.New("error comparing FDO public keys. Can not CBOR marshal pubKeyB")
	}

	if !bytes.Equal(aBytes, bBytes) {
		return errors.New("error comparing FDO public keys. Keys do not match")
	}

	return nil
}

type DeviceSgType int

const (
	StSECP256R1 DeviceSgType = -7
	StSECP384R1 DeviceSgType = -35
	StRSA2048   DeviceSgType = -257
	StRSA3072   DeviceSgType = -258
	StEPID10    DeviceSgType = 90
	StEPID11    DeviceSgType = 91
)

var DeviceSgTypeList []DeviceSgType = []DeviceSgType{
	StSECP256R1,
	StSECP384R1,
	StRSA2048,
	StRSA3072,
	// StEPID10, // TODO
	// StEPID11,
}

// Maps DEVICE supported SG type, to what OVEntry must use to, since device may not be able to handle some owner algorithms
var DeviceSgTypeOVMapping map[DeviceSgType]DeviceSgType = map[DeviceSgType]DeviceSgType{
	StSECP256R1: StSECP256R1,
	StSECP384R1: StSECP384R1,
	StRSA2048:   StSECP256R1,
	StRSA3072:   StSECP384R1,
	StEPID10:    StEPID10,
	StEPID11:    StEPID11,
}

type SigInfo struct {
	_      struct{} `cbor:",toarray"`
	SgType DeviceSgType
	Info   []byte
}

func (h SigInfo) Equal(bsiginfo SigInfo) error {
	if bsiginfo.SgType != h.SgType {
		return errors.New("sgTypes don't match")
	}

	if !bytes.Equal(bsiginfo.Info, h.Info) {
		return errors.New("info's don't match")
	}

	return nil
}

type CoseConsts int

const (
	CoseOKP           CoseConsts = 1
	CoseEC2           CoseConsts = 2
	CoseRSA           CoseConsts = 3
	CoseECDHESHKDF256 CoseConsts = -25
	CoseES256         CoseConsts = -7
)

type CosePublicKey struct {
	Kty    CoseConsts  `cbor:"1,keyasint"`
	Alg    CoseConsts  `cbor:"3,keyasint"`
	CrvOrN interface{} `cbor:"-1,keyasint,omitempty"` // Could be Curve(EC/ED) int or N(RSA) []byte
	XorE   []byte      `cbor:"-2,keyasint,omitempty"` // Could be X(EC/ED) []byte or E(RSA) []byte
	Y      []byte      `cbor:"-3,keyasint,omitempty"`
}

func GetDeviceSgType(pkType FdoPkType, hashType HashType) (DeviceSgType, error) {
	switch pkType {
	case SECP256R1:
		return StSECP256R1, nil
	case SECP384R1:
		return StSECP384R1, nil
	case RSA2048RESTR, RSAPKCS, RSAPSS:
		if hashType == HASH_SHA256 {
			return StRSA2048, nil
		} else if hashType == HASH_SHA384 {
			return StRSA3072, nil
		} else {
			return 0, fmt.Errorf("for RSA: %d is an unsupported hash type", hashType)
		}
	default:
		return 0, fmt.Errorf("for RSA: %d is an unsupported public key type", pkType)
	}
}

type SgTypeInfo struct {
	PkType   FdoPkType
	HashType HashType
	HmacType HashType
}

func GetAlgInfoFromSgType(sgType DeviceSgType) (*SgTypeInfo, error) {
	switch sgType {

	case StSECP256R1:
		return &SgTypeInfo{
			PkType:   SECP256R1,
			HashType: HASH_SHA256,
			HmacType: HASH_HMAC_SHA256,
		}, nil
	case StSECP384R1:
		return &SgTypeInfo{
			PkType:   SECP384R1,
			HashType: HASH_SHA384,
			HmacType: HASH_HMAC_SHA384,
		}, nil
	case StRSA2048:
		return &SgTypeInfo{
			PkType:   RSA2048RESTR,
			HashType: HASH_SHA256,
			HmacType: HASH_HMAC_SHA256,
		}, nil
	case StRSA3072:
		return &SgTypeInfo{
			PkType:   RSAPKCS,
			HashType: HASH_SHA384,
			HmacType: HASH_HMAC_SHA384,
		}, nil
	// case StEPID10:
	// 	break
	// case StEPID11:
	// 	break

	default:
		return nil, fmt.Errorf("unsupported sgType: %d", sgType)
	}
}
