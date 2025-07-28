package fdoshared

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

func VerifyCertificateChain(chain []X509CertificateBytes) ([]*x509.Certificate, error) {
	var finalChain []*x509.Certificate

	if len(chain) < 2 {
		return finalChain, errors.New("failed to verify certificate chain. The length must be at least two")
	}

	leafCertBytes := chain[0]
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return finalChain, errors.New("error decoding leaf certificate. " + err.Error())
	}

	rootCertBytes := chain[len(chain)-1]
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return finalChain, errors.New("error decoding root certificate. " + err.Error())
	}

	if !rootCert.IsCA {
		return finalChain, errors.New("root certificate is not a CA certificate")
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	interPool := x509.NewCertPool()

	if len(chain) > 2 {
		for i, interCertBytes := range chain[1 : len(chain)-1] {
			interCert, err := x509.ParseCertificate(interCertBytes)
			if err != nil {
				return finalChain, fmt.Errorf("error decoding intermediate %d certificate. %s", i, err.Error())
			}
			interPool.AddCert(interCert)
		}
	}

	verificationChain, err := leafCert.Verify(x509.VerifyOptions{
		Intermediates: interPool,
		Roots:         rootPool,
	})
	if err != nil {
		return nil, errors.New("error verifying certificate chain! " + err.Error())
	}
	finalChain = verificationChain[0]

	return finalChain, nil
}

func VerifyCoseSignatureWithCertificate(coseSig CoseSignature, pkType FdoPkType, certs []X509CertificateBytes) error {
	newPubKey := FdoPublicKey{
		PkType: pkType,
		PkEnc:  X5CHAIN,
		PkBody: certs,
	}

	return VerifyCoseSignature(coseSig, newPubKey)
}

func VerifySignature(payload []byte, signature []byte, publicKeyInst interface{}, pkType FdoPkType) error {
	switch pkType {
	case SECP256R1:
		if len(signature) != SECP256R1_SIG_LEN {
			return errors.New("for ES256, signature must be 64 bytes long")
		}

		pubKeyCasted, ok := publicKeyInst.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("error verifying SECP256R1 cose signature. Could not cast pubKey instance to ECDSA PubKey")
		}

		payloadHash := sha256.Sum256(payload)

		r := new(big.Int)
		r.SetBytes(signature[0:32])

		s := new(big.Int)
		s.SetBytes(signature[32:64])

		if !ecdsa.Verify(pubKeyCasted, payloadHash[:], r, s) {
			return errors.New("failed to verify signature")
		} else {
			return nil
		}
	case SECP384R1:
		if len(signature) != SECP384R1_SIG_LEN {
			return errors.New("for ES384, signature must be 96 bytes long")
		}

		pubKeyCasted, ok := publicKeyInst.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("error verifying SECP384R1 cose signature. Could not cast pubKey instance to ECDSA PubKey")
		}

		payloadHash := sha512.Sum384(payload)

		r := new(big.Int)
		r.SetBytes(signature[0:48])

		s := new(big.Int)
		s.SetBytes(signature[48:96])

		if !ecdsa.Verify(pubKeyCasted, payloadHash[:], r, s) {
			return errors.New("failed to verify signature")
		} else {
			return nil
		}
	case RSAPKCS, RSA2048RESTR:
		rsaPubKeyCasted, ok := publicKeyInst.(*rsa.PublicKey)
		if !ok {
			return errors.New("error verifying RS2RSAPKCS56 cose signature. Could not cast pubKey instance to RSA PubKey")
		}

		rsaPubKeyLen := len(rsaPubKeyCasted.N.Bytes())

		var hashingAlg crypto.Hash
		var payloadHash []byte
		if rsaPubKeyLen*8 == 2048 {
			hashingAlg = crypto.SHA256
			sPayloadHash := sha256.Sum256(payload)
			payloadHash = sPayloadHash[:]
		} else if rsaPubKeyLen*8 == 3072 {
			hashingAlg = crypto.SHA384
			sPayloadHash := sha512.Sum384(payload)
			payloadHash = sPayloadHash[:]
		} else {
			return fmt.Errorf("%d is an unsupported public key length for RSAPKCS", rsaPubKeyLen*8)
		}

		return rsa.VerifyPKCS1v15(rsaPubKeyCasted, hashingAlg, payloadHash, signature)
	case RSAPSS:
		return errors.New("RSAPSS is not currently implemented")
	default:
		return fmt.Errorf("PublicKey type %d is not supported", pkType)
	}
}

func VerifyCoseSignature(coseSig CoseSignature, publicKey FdoPublicKey) error {
	coseSigPayloadBytes, err := NewSig1Payload(coseSig.Protected, coseSig.Payload)
	if err != nil {
		return err
	}

	switch publicKey.PkEnc {
	case Crypto:
		return errors.New("ePID signatures are not currently supported")
	case X509:
		publicKeyCasted, ok := publicKey.PkBody.([]byte)
		if !ok {
			return errors.New("failed to cast pubkey PkBody to []byte")
		}

		pubKeyInst, err := x509.ParsePKIXPublicKey(publicKeyCasted)
		if err != nil {
			return errors.New("error parsing PKIX X509 Public Key. " + err.Error())
		}

		return VerifySignature(coseSigPayloadBytes, coseSig.Signature, pubKeyInst, publicKey.PkType)
	case X5CHAIN:
		decCertBytes, ok := publicKey.PkBody.([]X509CertificateBytes)
		if !ok {
			return errors.New("failed to cast pubkey PkBody to []X509CertificateBytes")
		}

		successChain, err := VerifyCertificateChain(decCertBytes)
		if err != nil {
			return err
		}

		leafCert := successChain[0]

		return VerifySignature(coseSigPayloadBytes, coseSig.Signature, leafCert.PublicKey, publicKey.PkType)

	case COSEKEY:
		publicKeyX509, err := CoseKeyToX509(publicKey)
		if err != nil {
			return err
		}

		pubKeyInst, err := x509.ParsePKIXPublicKey(publicKeyX509)
		if err != nil {
			return errors.New("error parsing PKIX X509 Public Key. " + err.Error())
		}

		return VerifySignature(coseSigPayloadBytes, coseSig.Signature, pubKeyInst, publicKey.PkType)

	default:
		return fmt.Errorf("PublicKey encoding %d is not supported", publicKey.PkEnc)
	}
}

func ExtractPrivateKey(privateKeyDer []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS1PrivateKey(privateKeyDer); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(privateKeyDer); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(privateKeyDer); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed to parse private key")
}

// https://crypto.stackexchange.com/a/50719
func i2osp(coeff []byte, expecteCoeffLen int) ([]byte, error) {
	// if len(rep(i)) is two larger or more than n then error;
	if len(coeff) >= expecteCoeffLen+2 {
		return nil, errors.New("i2osp: R/S coeff is too large")
	}

	if len(coeff) > expecteCoeffLen {
		if coeff[0] != 0x00 {
			// if len(rep(i)) is one larger and the leftmost byte isn't 00 then error;
			return nil, errors.New("i2osp: R/S coeff is too large")
		} else {
			// if len(rep(i)) is one larger and the leftmost byte is 00 then skip this byte and return the rest of rep(i) as answer;
			return coeff[1:], nil
		}
	}

	if len(coeff) < expecteCoeffLen {
		// if len(rep(i)) is smaller than n then left-pad with zero's until the representation is the same size as n.
		newCoeff := coeff
		for i := 0; i < expecteCoeffLen-len(coeff); i++ {
			newCoeff = append([]byte{0x00}, newCoeff...)
		}

		return newCoeff, nil
	}

	return coeff, nil
}

func GenerateCoseSignature(payload []byte, protected ProtectedHeader, unprotected UnprotectedHeader, privateKeyInterface interface{}, sgType SgType) (*CoseSignature, error) {
	protected.Alg = GetIntRef(int(sgType))

	protectedBytes, _ := CborCust.Marshal(protected)
	coseSigPayloadBytes, err := NewSig1Payload(protectedBytes, payload)
	if err != nil {
		return nil, err
	}

	var signature []byte

	switch sgType {
	case StSECP256R1:
		coeffLength := 32
		payloadHash := sha256.Sum256(coseSigPayloadBytes)
		privKeyCasted, ok := privateKeyInterface.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("error generating ES256 cose signature. Could not cast privKey instance to ECDSA PrivateKey")
		}

		if privKeyCasted.PublicKey.Curve.Params().Name != "P-256" {
			return nil, errors.New("error generating ES256 cose signature. Private key curve is not P-256")
		}

		r, s, err := ecdsa.Sign(rand.Reader, privKeyCasted, payloadHash[:])
		if err != nil {
			return nil, errors.New("error generating ES256 cose signature. " + err.Error())
		}

		Rb, err := i2osp(r.Bytes(), coeffLength)
		if err != nil {
			return nil, errors.New("error generating ES256 cose signature. " + err.Error())
		}

		Sb, err := i2osp(s.Bytes(), coeffLength)
		if err != nil {
			return nil, errors.New("error generating ES256 cose signature. " + err.Error())
		}

		signature = append(Rb, Sb...)
	case StSECP384R1:
		coeffLength := 48
		payloadHash := sha512.Sum384(coseSigPayloadBytes)

		privKeyCasted, ok := privateKeyInterface.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("error generating ES384 cose signature. Could not cast privKey instance to ECDSA PrivateKey")
		}

		if privKeyCasted.PublicKey.Curve.Params().Name != "P-384" {
			return nil, errors.New("error generating ES384 cose signature. Private key curve is not P-384")
		}

		r, s, err := ecdsa.Sign(rand.Reader, privKeyCasted, payloadHash[:])
		if err != nil {
			return nil, errors.New("error generating ES384 cose signature. " + err.Error())
		}

		Rb, err := i2osp(r.Bytes(), coeffLength)
		if err != nil {
			return nil, errors.New("error generating ES256 cose signature. " + err.Error())
		}

		Sb, err := i2osp(s.Bytes(), coeffLength)
		if err != nil {
			return nil, errors.New("error generating ES256 cose signature. " + err.Error())
		}

		signature = append(Rb, Sb...)
	case StRSA3072:
		payloadHash := sha512.Sum384(coseSigPayloadBytes)

		privKeyCasted, ok := privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("error generating RSA3072 cose signature. Could not cast privKey instance to RSA PrivateKey")
		}

		tSignature, err := rsa.SignPKCS1v15(rand.Reader, privKeyCasted, crypto.SHA384, payloadHash[:])
		if err != nil {
			return nil, errors.New("error generating RSA3072 cose signature. " + err.Error())
		}

		signature = tSignature
	case StRSA2048:
		payloadHash := sha256.Sum256(coseSigPayloadBytes)

		privKeyCasted, ok := privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("error generating RSA2048 cose signature. Could not cast privKey instance to RSA PrivateKey")
		}

		tSignature, err := rsa.SignPKCS1v15(rand.Reader, privKeyCasted, crypto.SHA256, payloadHash[:])
		if err != nil {
			return nil, errors.New("error generating RSA2048 cose signature. " + err.Error())
		}

		signature = tSignature
	case StEPID10, StEPID11:
		return nil, errors.New("StEPID10/StEPID11 is not currently implemented")
	default:
		return nil, fmt.Errorf("alg %d is not supported", sgType)
	}

	return &CoseSignature{
		Protected:   protectedBytes,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}, nil
}
