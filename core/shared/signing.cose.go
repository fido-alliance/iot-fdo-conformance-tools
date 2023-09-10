package fdoshared

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
)

type CoseConsts int

const (
	CoseOKP           CoseConsts = 1
	CoseEC2           CoseConsts = 2
	CoseRSA           CoseConsts = 3
	CoseECDHESHKDF256 CoseConsts = -25
	CoseES256         CoseConsts = -7
)

type CoseAlg int

const (
	CA_PKCS1_SHA1   CoseAlg = -65535
	CA_PSS_SHA256   CoseAlg = -3
	CA_PSS_SHA512   CoseAlg = -39
	CA_PSS_SHA384   CoseAlg = -38
	CA_PKCS1_SHA256 CoseAlg = -257
	CA_PKCS1_SHA384 CoseAlg = -258
	CA_PKCS1_SHA512 CoseAlg = -259
	CA_P256         CoseAlg = 1
	CA_P384         CoseAlg = 2
	CA_P521         CoseAlg = 3
)

var CoseAlgToHash map[CoseAlg]crypto.Hash = map[CoseAlg]crypto.Hash{
	CA_PKCS1_SHA1:   crypto.SHA1,
	CA_PSS_SHA256:   crypto.SHA256,
	CA_PSS_SHA512:   crypto.SHA512,
	CA_PSS_SHA384:   crypto.SHA384,
	CA_PKCS1_SHA256: crypto.SHA256,
	CA_PKCS1_SHA384: crypto.SHA384,
	CA_PKCS1_SHA512: crypto.SHA512,
	CA_P256:         crypto.SHA256,
	CA_P384:         crypto.SHA384,
	CA_P521:         crypto.SHA512,
}

type CosePublicKey struct {
	Kty    CoseConsts  `cbor:"1,keyasint"`
	Alg    CoseAlg     `cbor:"3,keyasint"`
	CrvOrN interface{} `cbor:"-1,keyasint,omitempty"` // Could be Curve(EC/ED) int or N(RSA) []byte
	XorE   []byte      `cbor:"-2,keyasint,omitempty"` // Could be X(EC/ED) []byte or E(RSA) []byte
	Y      []byte      `cbor:"-3,keyasint,omitempty"`
}

func CoseKeyToX509(pubKey FdoPublicKey) ([]byte, error) {
	var algId CoseAlg
	var rawPublicKey []byte

	switch pubKey.PkEnc {
	case COSEKEY:
		cosePubKey, ok := pubKey.PkBody.(CosePublicKey)
		if !ok {
			return nil, errors.New("error converting COSE public key. Could not cast pubKey instance to COSE PubKey")
		}

		switch cosePubKey.Kty {
		case CoseEC2:
			x := cosePubKey.XorE
			y := cosePubKey.Y

			xy := append(x, y...)
			rawPublicKey = append([]byte{0x04}, xy...)
			algId = cosePubKey.CrvOrN.(CoseAlg)
		case CoseRSA:
			rawPublicKey = cosePubKey.CrvOrN.([]byte)
			algId = cosePubKey.Alg
		case CoseOKP:
			return nil, errors.New("unsupported COSE key type: OKP")
		default:
			return nil, fmt.Errorf("unsupported COSE key type: %d", cosePubKey.Kty)
		}

	default:
		return nil, fmt.Errorf("unsupported public key encoding: %d", pubKey.PkEnc)
	}

	switch algId {
	case CA_P256:
		buff, _ := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200")
		return append(buff, rawPublicKey...), nil
	case CA_P384:
		buff, _ := hex.DecodeString("3076301006072a8648ce3d020106052b81040022036200")
		return append(buff, rawPublicKey...), nil
	case CA_P521:
		buff, _ := hex.DecodeString("30819b301006072a8648ce3d020106052b8104002303818600")
		return append(buff, rawPublicKey...), nil
	case CA_PKCS1_SHA256, CA_PKCS1_SHA384, CA_PKCS1_SHA512:
		if len(rawPublicKey) < 512 { // 2080 key
			pkcsHeader, _ := hex.DecodeString("30820122300d06092a864886f70d01010105000382010f003082010a0282010100")
			pkcsEXP, _ := hex.DecodeString("0203010001")

			if len(rawPublicKey) > 256 {
				rawPublicKey = rawPublicKey[1:]
			}

			return append(append(pkcsHeader, rawPublicKey...), pkcsEXP...), nil
		} else if len(rawPublicKey) >= 512 || len(rawPublicKey) == 513 {
			pkcsHeader, _ := hex.DecodeString("30820222300d06092a864886f70d01010105000382020f003082020a0282020100")
			pkcsEXP, _ := hex.DecodeString("0203010001")

			if len(rawPublicKey) > 512 {
				rawPublicKey = rawPublicKey[1:]
			}

			return append(append(pkcsHeader, rawPublicKey...), pkcsEXP...), nil
		} else {
			return nil, fmt.Errorf("unsupported key size: %d", len(rawPublicKey))
		}
	default:
		return nil, fmt.Errorf("unsupported COSE key type: %d", algId)
	}
}
