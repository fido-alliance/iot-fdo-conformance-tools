package fdoshared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/fido-alliance/dhkx"
)

type KexSuiteName string

const (
	// “ECDH256”: The ECDH method uses a standard Diffie-Hellman mechanism for ECDSA keys. The ECC keys follow NIST P-256 (SECP256R1)
	KEX_ECDH256 KexSuiteName = "ECDH256"

	// “ECDH384”: Standard Diffie-Hellman mechanism ECC NIST P-384 (SECP384R1)
	KEX_ECDH384 KexSuiteName = "ECDH384"

	// “DHKEXid14”: Diffie-Hellman key exchange method using a standard Diffie-Hellman mechanism with a standard NIST exponent and 2048-bit modulus ([RFC3526], id 14). This is the preferred method for RSA2048RESTR Owner keys.
	KEX_DHKEXid14 KexSuiteName = "DHKEXid14"

	// “DHKEXid15”: Diffie-Hellman key exchange method using a standard Diffie-Hellman mechanism with a standard National Institute of Standards and Technology (NIST) exponent and 3072-bit modulus. ([RFC3526], id 15), This is the preferred method for RSA 3072-bit Owner keys.
	KEX_DHKEXid15 KexSuiteName = "DHKEXid15"

	// “ASYMKEX2048”: Asymmetric key exchange method uses the encryption by an Owner key based on RSA2048RESTR; this method is useful in FIDO Device Onboard Client environments where Diffie-Hellman computation is slow or difficult to code.
	KEX_ASYMKEX2048 KexSuiteName = "ASYMKEX2048"

	// “ASYMKEX3072”: The Asymmetric key exchange method uses the encryption by an Owner key based on RSA with 3072-bit key.
	KEX_ASYMKEX3072 KexSuiteName = "ASYMKEX3072"
)

const (
	KEX_ECDH256_RANDOM_LEN     int = 128 / 8
	KEX_ECDH384_RANDOM_LEN     int = 384 / 8
	KEX_ASYMKEX2048_RANDOM_LEN int = 256 / 8
	KEX_ASYMKEX3072_RANDOM_LEN int = 768 / 8
)

var KexSuitNames [6]KexSuiteName = [6]KexSuiteName{
	KEX_ECDH256,
	KEX_ECDH384,
	KEX_DHKEXid14,
	KEX_DHKEXid15,
	KEX_ASYMKEX2048,
	KEX_ASYMKEX3072,
}

var SgTypeToKexSuitName = map[SgType]KexSuiteName{
	StSECP256R1: KEX_ECDH256,
	StSECP384R1: KEX_ECDH384,
	StRSA2048:   KEX_DHKEXid14,
	StRSA3072:   KEX_DHKEXid15,
}

type KeXParams struct {
	_             struct{} `cbor:",toarray"`
	Private       []byte
	XAKeyExchange []byte
	KexSuit       KexSuiteName
}

type DHKexPrivateKey struct {
	_       struct{} `cbor:",toarray"`
	X       []byte
	Y       []byte
	GroupID dhkx.GroupID
}

type SessionKeyInfo struct {
	_           struct{} `cbor:",toarray"`
	ShSe        []byte
	ContextRand []byte
}

func NewDHKexPrivateKey(x []byte, y []byte, groupID dhkx.GroupID) DHKexPrivateKey {
	return DHKexPrivateKey{
		X:       x,
		Y:       y,
		GroupID: groupID,
	}
}

func (h *DHKexPrivateKey) MarshalCbor() []byte {
	resultBytes, _ := CborCust.Marshal(*h)
	return resultBytes
}

func (h *DHKexPrivateKey) UnmarshalCbor(cborBytes []byte) error {
	return CborCust.Unmarshal(cborBytes, h)
}

func (h *DHKexPrivateKey) GetDHKEXPrivateKeyInst() *dhkx.DHKey {
	group, _ := dhkx.GetGroup(h.GroupID)
	dhKex := dhkx.DHKey{
		X:     big.NewInt(0).SetBytes(h.X),
		Y:     big.NewInt(0).SetBytes(h.Y),
		Group: group,
	}

	return &dhKex
}

func GenerateXABKeyExchange(kexSuitName KexSuiteName, ownerPubKey *FdoPublicKey) (*KeXParams, error) {
	switch kexSuitName {
	case KEX_DHKEXid14:
		g, _ := dhkx.GetGroup(dhkx.DHKX_ID14)

		priv, err := g.GeneratePrivateKey(nil)
		if err != nil {
			return nil, errors.New("error while generating DHKEX ID14 key: " + err.Error())
		}

		privKeyStruct := NewDHKexPrivateKey(priv.X.Bytes(), priv.Y.Bytes(), dhkx.DHKX_ID14)

		resultKex := KeXParams{
			Private:       privKeyStruct.MarshalCbor(),
			XAKeyExchange: priv.MarshalPublicKey(),
			KexSuit:       kexSuitName,
		}

		return &resultKex, nil

	case KEX_DHKEXid15:
		g, _ := dhkx.GetGroup(dhkx.DHKX_ID15)

		priv, err := g.GeneratePrivateKey(nil)
		if err != nil {
			return nil, errors.New("error while generating DHKEX ID15 key: " + err.Error())
		}

		privKeyStruct := NewDHKexPrivateKey(priv.X.Bytes(), priv.Y.Bytes(), dhkx.DHKX_ID15)

		resultKex := KeXParams{
			Private:       privKeyStruct.MarshalCbor(),
			XAKeyExchange: priv.MarshalPublicKey(),
			KexSuit:       kexSuitName,
		}

		return &resultKex, nil

	case KEX_ECDH256:
		ownerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.New("error while generating ECDH key: " + err.Error())
		}

		ownerRandom := NewRandomBuffer(int(KEX_ECDH256_RANDOM_LEN))

		ownerRandomLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(ownerRandomLenBytes, uint16(len(ownerRandom)))
		ownerBlock := append(ownerRandomLenBytes, ownerRandom...)

		xBytes := ownerKey.X.Bytes()
		xLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(xLenBytes, uint16(len(xBytes)))
		xBlock := append(xLenBytes, xBytes...)

		yBytes := ownerKey.Y.Bytes()
		yLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(yLenBytes, uint16(len(yBytes)))
		yBlock := append(yLenBytes, yBytes...)

		publicKeyBlock := append(xBlock, yBlock...)

		xAKeyExchange := append(publicKeyBlock, ownerBlock...)

		resultKex := KeXParams{
			Private:       ownerKey.D.Bytes(),
			XAKeyExchange: xAKeyExchange,
			KexSuit:       kexSuitName,
		}

		return &resultKex, nil

	case KEX_ECDH384:
		ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, errors.New("error generating ECDH key: " + err.Error())
		}

		ownerRandom := NewRandomBuffer(KEX_ECDH384_RANDOM_LEN)

		ownerRandomLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(ownerRandomLenBytes, uint16(len(ownerRandom)))
		ownerBlock := append(ownerRandomLenBytes, ownerRandom...)

		xBytes := ownerKey.X.Bytes()
		xLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(xLenBytes, uint16(len(xBytes)))
		xBlock := append(xLenBytes, xBytes...)

		yBytes := ownerKey.Y.Bytes()
		yLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(yLenBytes, uint16(len(yBytes)))
		yBlock := append(yLenBytes, yBytes...)

		publicKeyBlock := append(xBlock, yBlock...)

		xAKeyExchange := append(publicKeyBlock, ownerBlock...)

		resultKex := KeXParams{
			Private:       ownerKey.D.Bytes(),
			XAKeyExchange: xAKeyExchange,
			KexSuit:       kexSuitName,
		}

		return &resultKex, nil

	case KEX_ASYMKEX2048, KEX_ASYMKEX3072:
		var kexLen int
		if kexSuitName == KEX_ASYMKEX2048 {
			kexLen = KEX_ASYMKEX2048_RANDOM_LEN
		} else {
			kexLen = KEX_ASYMKEX3072_RANDOM_LEN
		}

		ownerDeviceRandom := NewRandomBuffer(kexLen)
		resultKex := KeXParams{
			Private:       ownerDeviceRandom,
			XAKeyExchange: ownerDeviceRandom,
			KexSuit:       kexSuitName,
		}

		if ownerPubKey != nil {
			ownerRandom, err := WrapOAEP(ownerDeviceRandom, *ownerPubKey)
			if err != nil {
				return nil, errors.New("error generating ASYM KEX XBKex. " + err.Error())
			}

			resultKex.XAKeyExchange = ownerRandom
		}

		return &resultKex, nil

	default:
		return nil, fmt.Errorf("unknown KeyExchange algorithm: %s", kexSuitName)
	}
}

func DeriveSessionKey(kexA KeXParams, xBKeyExchange []byte, isDevice bool, ownerPrivateKey interface{}) (*SessionKeyInfo, error) {
	switch kexA.KexSuit {
	case KEX_DHKEXid14, KEX_DHKEXid15:
		privKeyStruct := DHKexPrivateKey{}
		privKeyStruct.UnmarshalCbor(kexA.Private)

		dhkxPrivKeyA := privKeyStruct.GetDHKEXPrivateKeyInst()

		// Recover Bob's public key
		dhkxBPubKey := dhkx.NewPublicKey(xBKeyExchange)

		// Compute the key
		sharedPubKey, err := dhkxPrivKeyA.Group.ComputeKey(dhkxBPubKey, dhkxPrivKeyA)
		if err != nil {
			return nil, fmt.Errorf("error deriving shared key for KEX_DHKEX id14/id15. %s", err.Error())
		}

		return &SessionKeyInfo{
			ShSe:        sharedPubKey.MarshalPublicKey(),
			ContextRand: []byte{},
		}, nil

	case KEX_ECDH256:
		expectedLen := 2 + 32 + 2 + 32 + 2 + KEX_ECDH256_RANDOM_LEN
		if len(xBKeyExchange) != expectedLen {
			return nil, fmt.Errorf("unexpected xBKeyExchange for ECDH256 length. Expected %d bytes long", expectedLen)
		}

		deviceX := xBKeyExchange[2:34]
		deviceY := xBKeyExchange[36:68]
		xbRandom := xBKeyExchange[70:86]

		devicePubKey := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(deviceX),
			Y:     new(big.Int).SetBytes(deviceY),
		}

		ownerX := kexA.XAKeyExchange[2:34]
		ownerY := kexA.XAKeyExchange[36:68]
		xaRandom := kexA.XAKeyExchange[70:86]

		ownerPrivateKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ownerX),
				Y:     new(big.Int).SetBytes(ownerY),
			},
			D: new(big.Int).SetBytes(kexA.Private),
		}

		Shx, _ := ownerPrivateKey.PublicKey.Curve.ScalarMult(devicePubKey.X, devicePubKey.Y, ownerPrivateKey.D.Bytes())

		var randomSuffix []byte
		if isDevice {
			randomSuffix = append(xaRandom, xbRandom...)
		} else {
			randomSuffix = append(xbRandom, xaRandom...)
		}

		shSe := append(Shx.Bytes(), randomSuffix...)

		return &SessionKeyInfo{
			ShSe:        shSe,
			ContextRand: []byte{},
		}, nil

	case KEX_ECDH384:
		expectedLen := 2 + 48 + 2 + 48 + 2 + KEX_ECDH384_RANDOM_LEN
		if len(xBKeyExchange) != expectedLen {
			return nil, fmt.Errorf("unexpected xBKeyExchange for ECDH384 length. Expected %d bytes long", expectedLen)
		}

		deviceX := xBKeyExchange[2:50]
		deviceY := xBKeyExchange[52:100]
		xbRandom := xBKeyExchange[102:150]

		devicePubKey := ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(deviceX),
			Y:     new(big.Int).SetBytes(deviceY),
		}

		ownerX := kexA.XAKeyExchange[2:50]
		ownerY := kexA.XAKeyExchange[52:100]
		xaRandom := kexA.XAKeyExchange[102:150]

		ownerPrivateKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     new(big.Int).SetBytes(ownerX),
				Y:     new(big.Int).SetBytes(ownerY),
			},
			D: new(big.Int).SetBytes(kexA.Private),
		}

		Shx, _ := ownerPrivateKey.PublicKey.Curve.ScalarMult(devicePubKey.X, devicePubKey.Y, ownerPrivateKey.D.Bytes())

		var randomSuffix []byte
		if isDevice {
			randomSuffix = append(xaRandom, xbRandom...)
		} else {
			randomSuffix = append(xbRandom, xaRandom...)
		}

		shSe := append(Shx.Bytes(), randomSuffix...)

		return &SessionKeyInfo{
			ShSe:        shSe,
			ContextRand: []byte{},
		}, nil

	case KEX_ASYMKEX2048, KEX_ASYMKEX3072:
		if isDevice {
			return &SessionKeyInfo{
				ShSe:        kexA.Private,
				ContextRand: xBKeyExchange,
			}, nil
		} else {
			deviceRandom, err := UnwrapOAEP(xBKeyExchange, ownerPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("error unwrapping OAEP for ASYM KEX. %s", err.Error())
			}

			return &SessionKeyInfo{
				ShSe:        deviceRandom,
				ContextRand: kexA.Private,
			}, nil
		}
	default:
		return nil, fmt.Errorf("unknown KeyExchange algorithm: %s", kexA.KexSuit)
	}
}

func WrapOAEP(message []byte, ownerPubKey FdoPublicKey) ([]byte, error) {
	publicKeyCasted, ok := ownerPubKey.PkBody.([]byte)
	if !ok {
		return nil, errors.New("failed to cast pubkey PkBody to []byte")
	}

	pubKeyInst, err := x509.ParsePKIXPublicKey(publicKeyCasted)
	if err != nil {
		return nil, errors.New("error parsing PKIX X509 Public Key. " + err.Error())
	}

	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKeyInst.(*rsa.PublicKey), message, []byte{})
	if err != nil {
		return nil, errors.New("error wrapping OAEP. " + err.Error())
	}

	return ciphertext, nil
}

func UnwrapOAEP(ciphertext []byte, privateKeyInterface interface{}) ([]byte, error) {
	hash := sha256.New()
	message, err := rsa.DecryptOAEP(hash, rand.Reader, privateKeyInterface.(*rsa.PrivateKey), ciphertext, []byte{})
	if err != nil {
		return nil, errors.New("error unwrapping OAEP. " + err.Error())
	}

	return message, nil
}
