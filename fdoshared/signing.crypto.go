package fdoshared

type UnprotectedHeader struct {
}

type ProtectedHeader struct {
}

type CoseSignature struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected UnprotectedHeader
	Payload     []byte
	Signature   []byte
}

type FdoPkType uint8

const (
	RSA2048RESTR FdoPkType = 1  // RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
	RSAPKCS      FdoPkType = 5  // RSA key, PKCS1, v1.5
	RSAPSS       FdoPkType = 6  // RSA key, PSS
	SECP256R1    FdoPkType = 10 // ECDSA secp256r1 = NIST-P-256 = prime256v1
	SECP384R1    FdoPkType = 11 // ECDSA secp384r1 = NIST-P-384
)

type FdoPkEnc uint8

const (
	Crypto  FdoPkEnc = 0
	X509    FdoPkEnc = 1
	X5CHAIN FdoPkEnc = 2
	COSEKEY FdoPkEnc = 3
)

type FdoPublicKey struct {
	_      struct{} `cbor:",toarray"`
	PkType FdoPkType
	PkEnc  FdoPkEnc
	PkBody []byte
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

type SigInfo struct {
	_      struct{} `cbor:",toarray"`
	SgType DeviceSgType
	Info   string
}

func VerifyCoseSignature(coseSig CoseSignature, publicKey FdoPublicKey) (bool, error) {
	// TODO
	return true, nil
}
