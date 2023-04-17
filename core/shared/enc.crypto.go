package fdoshared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/fxamacker/cbor/v2"
)

type CipherSuiteName int

const (
	CIPHER_A128GCM            CipherSuiteName = 1
	CIPHER_A256GCM            CipherSuiteName = 3
	CIPHER_AES_CCM_16_128_128 CipherSuiteName = 30 //prev spec uses 32 and 33 64
	CIPHER_AES_CCM_16_128_256 CipherSuiteName = 31
	CIPHER_AES_CCM_64_128_128 CipherSuiteName = 32 //prev spec uses 32 and 33 64
	CIPHER_AES_CCM_64_128_256 CipherSuiteName = 33
	CIPHER_COSE_AES128_CBC    CipherSuiteName = -17760703 // CS_AES128_CBC_HMAC-SHA256
	CIPHER_COSE_AES128_CTR    CipherSuiteName = -17760704 // CS_AES128_CTR_HMAC-SHA256
	CIPHER_COSE_AES256_CBC    CipherSuiteName = -17760705 // CS_AES256_CTR_HMAC-SHA384
	CIPHER_COSE_AES256_CTR    CipherSuiteName = -17760706 // CS_AES256_CBC_HMAC-SHA384
)

type CipherInfo struct {
	CryptoAlg  CipherSuiteName
	HmacAlg    HashType
	HashAlg    HashType
	IvLen      int
	SekLen     int // Len of encryption key for CTR/CBC
	SvkLen     int // Len of verification key for CTR/CBC
	SevkLength int // Len of encryption and verification key for GCM/CCM
}

var CipherSuitesInfoMap map[CipherSuiteName]CipherInfo = map[CipherSuiteName]CipherInfo{
	CIPHER_COSE_AES128_CBC: {
		CryptoAlg: CIPHER_COSE_AES128_CBC,
		HmacAlg:   HASH_HMAC_SHA256,
		HashAlg:   HASH_SHA256,
		IvLen:     16,
		SekLen:    16,
		SvkLen:    32,
	},
	CIPHER_COSE_AES128_CTR: {
		CryptoAlg: CIPHER_COSE_AES128_CTR,
		HmacAlg:   HASH_HMAC_SHA256,
		HashAlg:   HASH_SHA256,
		IvLen:     16,
		SekLen:    16,
		SvkLen:    32,
	},
	CIPHER_COSE_AES256_CBC: {
		CryptoAlg: CIPHER_COSE_AES256_CBC,
		HmacAlg:   HASH_HMAC_SHA384,
		HashAlg:   HASH_SHA384,
		IvLen:     32,
		SekLen:    32,
		SvkLen:    64,
	},
	CIPHER_COSE_AES256_CTR: {
		CryptoAlg: CIPHER_COSE_AES256_CTR,
		HmacAlg:   HASH_HMAC_SHA384,
		HashAlg:   HASH_SHA384,
		IvLen:     32,
		SekLen:    32,
		SvkLen:    64,
	},
	CIPHER_A128GCM: {
		CryptoAlg:  CIPHER_A128GCM,
		HmacAlg:    HASH_HMAC_SHA256,
		HashAlg:    HASH_SHA256,
		IvLen:      12,
		SevkLength: 16,
	},
	CIPHER_A256GCM: {
		CryptoAlg:  CIPHER_A256GCM,
		HmacAlg:    HASH_HMAC_SHA256,
		HashAlg:    HASH_SHA256,
		IvLen:      12,
		SevkLength: 32,
	},
	// CIPHER_AES_CCM_16_128_128: {
	// 	CryptoAlg: CIPHER_AES_CCM_16_128_128,
	// 	SevkLength: 32,

	// }
}

/*
COSE_Mac0[
    {1:5}, # protected: alg:SHA256
    {},    # unprotected
    COSE_Encrypt0[
        {1:AESPlainType} # protected
		{5:h'--*iv*--'}, #unprotected
		h'--*AES*-*encrypted*-*CBOR*--'
    ],
    h'--*hmac*-*bytes*---'
]
*/

// Authenticated Encrypted data
type ETMOuterBlock struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte   // ETMMacType = { 1: MacType }
	Unprotected UnprotectedHeader
	Payload     []byte // Encoded ETMInnerBlock
	Tag         []byte // HMAC os the payload
}

const CONST_HMAC_COSE_LABEL_MAC0 = "MAC0"

type COSEMacStructure struct {
	_           struct{} `cbor:",toarray"`
	Context     string
	Protected   ProtectedHeader
	ExternalAAD []byte
	Ciphertext  []byte
}

type ETMInnerBlock struct {
	_           struct{}          `cbor:",toarray"`
	Protected   []byte            // { ALG 1:AESPlainType }
	Unprotected UnprotectedHeader // { IV 5:AESIV }
	Ciphertext  []byte            // Encrypted data ENC_0 COSE
}

const CONST_ENC_COSE_LABEL_ENC0 = "Encrypt0"

type COSEEncStructure struct { // It's just a god damn AAD FFS!
	_           struct{} `cbor:",toarray"`
	Context     string
	Protected   ProtectedHeader
	ExternalAAD []byte
}

const CONST_KDF_LABEL = "FIDO-KDF"
const CONST_KDF_CONTEXT = "AutomaticOnboardTunnel"

// Implementation of SP800-108 section 5.1 KDF in Counter Mode
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
func Sp800108CounterKDF(sizeBytes int, hmacAlg HashType, key []byte, contextRand []byte) ([]byte, error) {
	var mac hash.Hash
	if hmacAlg == HASH_HMAC_SHA256 {
		mac = hmac.New(sha256.New, key)
	} else if hmacAlg == HASH_HMAC_SHA384 {
		mac = hmac.New(sha512.New384, key)
	} else {
		return nil, fmt.Errorf("Unknown HMAC algorithm! %d", hmacAlg)
	}

	h := mac.Size() * 8
	l := sizeBytes * 8

	n := int(math.Ceil(float64(l) / float64(h)))

	result := []byte{}

	for i := 0; i < n; i += 1 {
		mac.Write([]byte{byte(i)})
		mac.Write([]byte(CONST_KDF_LABEL))
		mac.Write([]byte{byte(0x00)}) // Separator
		mac.Write([]byte(CONST_KDF_CONTEXT))
		mac.Write(contextRand)
		l2 := []byte{byte((l >> 8) & 0xff), byte((l & 0xff))}
		mac.Write(l2)

		result = append(result, mac.Sum(nil)...)
		mac.Reset()
	}

	return result[0:sizeBytes], nil
}

func encryptETM(plaintext []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	var algInfo = CipherSuitesInfoMap[cipherSuite]

	// INNER ENCRYPTION BLOCK
	protectedHeaderInner := ProtectedHeader{
		Alg: int(algInfo.CryptoAlg),
	}

	protectedHeaderBytes, err := cbor.Marshal(protectedHeaderInner)
	if err != nil {
		return nil, errors.New("Error encoding protected header. " + err.Error())
	}

	IvBytes := make([]byte, algInfo.IvLen)
	rand.Read(IvBytes)

	unprotectedHeaderInner := UnprotectedHeader{
		AESIV: IvBytes,
	}

	svksek, err := Sp800108CounterKDF(algInfo.SekLen+algInfo.SvkLen, algInfo.HmacAlg, sessionKeyInfo.ShSe, sessionKeyInfo.ContextRand)
	if err != nil {
		return nil, errors.New("Error generating SVK/SEK! " + err.Error())
	}

	svk := svksek[0:algInfo.SvkLen]
	sek := svksek[algInfo.SvkLen : algInfo.SvkLen+algInfo.SekLen]

	var ciphertext = make([]byte, len(plaintext))

	block, err := aes.NewCipher(sek)
	if err != nil {
		return nil, errors.New("Error creating new cipher. " + err.Error())
	}

	switch algInfo.CryptoAlg {
	case CIPHER_COSE_AES128_CTR:
		stream := cipher.NewCTR(block, IvBytes)
		stream.XORKeyStream(ciphertext, plaintext)
	default:
		return nil, errors.New("%s Error encoding inner ETM. " + err.Error())
	}

	innerBlock := ETMInnerBlock{
		Protected:   protectedHeaderBytes,
		Unprotected: unprotectedHeaderInner,
		Ciphertext:  ciphertext,
	}

	innerBlockBytes, err := cbor.Marshal(innerBlock)
	if err != nil {
		return nil, errors.New("Error encoding inner ETM. " + err.Error())
	}

	// OUTER HMAC BLOCK

	outerProtectedHeader := ProtectedHeader{
		Alg: int(algInfo.HmacAlg),
	}
	outerProtectedHeaderBytes, _ := cbor.Marshal(outerProtectedHeader)

	outerUnprotectedHeader := UnprotectedHeader{}

	coseMacStruct := COSEMacStructure{
		Context:     CONST_HMAC_COSE_LABEL_MAC0,
		Protected:   outerProtectedHeader,
		ExternalAAD: []byte{},
		Ciphertext:  innerBlockBytes,
	}
	coseMacStructBytes, _ := cbor.Marshal(coseMacStruct)

	fdoMac, err := GenerateFdoHmac(coseMacStructBytes, algInfo.HmacAlg, svk)
	if err != nil {
		return nil, errors.New("Error generating HMAC! " + err.Error())
	}

	outerBlock := ETMOuterBlock{
		Protected:   outerProtectedHeaderBytes,
		Unprotected: outerUnprotectedHeader,
		Payload:     innerBlockBytes,
		Tag:         fdoMac.Hash,
	}

	outerBlockBytes, err := cbor.Marshal(outerBlock)
	if err != nil {
		return nil, errors.New("Error while encoding outer block! " + err.Error())
	}
	return outerBlockBytes, nil
}

func decryptETM(encrypted []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	var outer ETMOuterBlock
	err := cbor.Unmarshal(encrypted, &outer)
	if err != nil {
		return nil, errors.New("Error decoding encrypted block. " + err.Error())
	}

	var outerProtected ProtectedHeader
	err = cbor.Unmarshal(outer.Protected, &outerProtected)
	if err != nil {
		return nil, errors.New("Error decoding protected header. " + err.Error())
	}

	var algInfo = CipherSuitesInfoMap[cipherSuite]

	svksek, err := Sp800108CounterKDF(algInfo.SekLen+algInfo.SvkLen, algInfo.HmacAlg, sessionKeyInfo.ShSe, sessionKeyInfo.ContextRand)
	if err != nil {
		return nil, errors.New("Error generating SVK/SEK! " + err.Error())
	}

	svk := svksek[0:algInfo.SvkLen]
	sek := svksek[algInfo.SvkLen : algInfo.SvkLen+algInfo.SekLen]

	coseMacStruct := COSEMacStructure{
		Context:     CONST_HMAC_COSE_LABEL_MAC0,
		Protected:   outerProtected,
		ExternalAAD: []byte{},
		Ciphertext:  outer.Payload,
	}
	coseMacStructBytes, _ := cbor.Marshal(coseMacStruct)

	err = VerifyHMac(coseMacStructBytes, HashOrHmac{
		Type: algInfo.HmacAlg,
		Hash: outer.Tag,
	}, svk)
	if err != nil {
		return nil, errors.New("Error verifying HMAC! " + err.Error())
	}

	// Inner ETM block
	var inner ETMInnerBlock
	err = cbor.Unmarshal(outer.Payload, &inner)
	if err != nil {
		return nil, errors.New("Error decoding inner protected header. " + err.Error())
	}

	var innerProtected ProtectedHeader
	err = cbor.Unmarshal(inner.Protected, &innerProtected)
	if err != nil {
		return nil, errors.New("Error decoding protected header. " + err.Error())
	}

	if innerProtected.Alg != int(algInfo.CryptoAlg) {
		return nil, errors.New("Error! Encryption algorithms don't match!")
	}

	IvBytes := inner.Unprotected.AESIV

	block, err := aes.NewCipher(sek)
	if err != nil {
		return nil, errors.New("Error creating new cipher. " + err.Error())
	}

	plaintext := make([]byte, len(inner.Ciphertext))
	switch innerProtected.Alg {
	case int(CIPHER_COSE_AES128_CTR):
		stream := cipher.NewCTR(block, IvBytes)
		stream.XORKeyStream(plaintext, inner.Ciphertext)
	default:
		return nil, fmt.Errorf("Unsupported encryption algorithm! %d", innerProtected.Alg)
	}

	return plaintext, nil
}

/*
;;Simple encrypted message, using one COSE
;; (authenticated) encryption mechanism.
EMBlock = [
    protected:   { 1:COSEEncType },
    unprotected: { COSEUnProtFields }
    ciphertext:     bstr # encrypted ProtocolMessage
]
*/
type EMBlock struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte   // ETMMacType = { 1: MacType }
	Unprotected UnprotectedHeader
	Ciphertext  []byte
}

func encryptEMB(plaintext []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	var algInfo = CipherSuitesInfoMap[cipherSuite]

	// INNER ENCRYPTION BLOCK
	protectedHeaderInner := ProtectedHeader{
		Alg: int(algInfo.CryptoAlg),
	}

	protectedHeaderBytes, err := cbor.Marshal(protectedHeaderInner)
	if err != nil {
		return nil, errors.New("Error encoding protected header. " + err.Error())
	}

	IvBytes := make([]byte, algInfo.IvLen)
	rand.Read(IvBytes)

	unprotectedHeaderInner := UnprotectedHeader{
		AESIV: IvBytes,
	}

	sevk, err := Sp800108CounterKDF(algInfo.SevkLength, algInfo.HmacAlg, sessionKeyInfo.ShSe, sessionKeyInfo.ContextRand)
	if err != nil {
		return nil, errors.New("Error generating SEVK! " + err.Error())
	}

	var ciphertext []byte

	block, err := aes.NewCipher(sevk)
	if err != nil {
		return nil, errors.New("Error creating new cipher. " + err.Error())
	}

	switch algInfo.CryptoAlg {
	case CIPHER_A128GCM, CIPHER_A256GCM:
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return []byte{}, errors.New("Error generating new GCM instance. " + err.Error())
		}

		ciphertext = aesgcm.Seal(nil, IvBytes, plaintext, nil)
	default:
		return nil, errors.New("%s Error encoding EMB. " + err.Error())
	}

	innerBlock := EMBlock{
		Protected:   protectedHeaderBytes,
		Unprotected: unprotectedHeaderInner,
		Ciphertext:  ciphertext,
	}

	innerBlockBytes, err := cbor.Marshal(innerBlock)
	if err != nil {
		return nil, errors.New("Error encoding EMB. " + err.Error())
	}

	return innerBlockBytes, nil
}

func decryptEMB(encrypted []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	var algInfo = CipherSuitesInfoMap[cipherSuite]

	sevk, err := Sp800108CounterKDF(algInfo.SevkLength, algInfo.HmacAlg, sessionKeyInfo.ShSe, sessionKeyInfo.ContextRand)
	if err != nil {
		return nil, errors.New("Error generating SVK/SEK! " + err.Error())
	}

	var embInst EMBlock
	err = cbor.Unmarshal(encrypted, &embInst)
	if err != nil {
		return nil, errors.New("Error decoding inner protected header. " + err.Error())
	}

	var protected ProtectedHeader
	err = cbor.Unmarshal(embInst.Protected, &protected)
	if err != nil {
		return nil, errors.New("Error decoding protected header. " + err.Error())
	}

	if protected.Alg != int(algInfo.CryptoAlg) {
		return nil, errors.New("Error! Encryption algorithms don't match!")
	}

	IvBytes := embInst.Unprotected.AESIV

	block, err := aes.NewCipher(sevk)
	if err != nil {
		return nil, errors.New("Error creating new cipher. " + err.Error())
	}

	var plaintext []byte
	switch algInfo.CryptoAlg {
	case CIPHER_A128GCM, CIPHER_A256GCM:
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return []byte{}, errors.New("Error generating new GCM instance. " + err.Error())
		}

		prepPlaintext, err := aesgcm.Open(nil, IvBytes, embInst.Ciphertext, nil)
		if err != nil {
			return []byte{}, errors.New("Error decrypting EMB. " + err.Error())
		}

		plaintext = prepPlaintext
	default:
		return nil, errors.New("%s Error encoding EMB. " + err.Error())
	}

	return plaintext, nil
}

func AddEncryptionWrapping(payload []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	switch cipherSuite {
	case CIPHER_COSE_AES128_CBC, CIPHER_COSE_AES128_CTR, CIPHER_COSE_AES256_CBC, CIPHER_COSE_AES256_CTR:
		return encryptETM(payload, sessionKeyInfo, cipherSuite)
	case CIPHER_A128GCM, CIPHER_A256GCM:
		return encryptEMB(payload, sessionKeyInfo, cipherSuite)
	default:
		return nil, fmt.Errorf("Unsupported encryption scheme! %s", cipherSuite)
	}
}

func RemoveEncryptionWrapping(encryptedPayload []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	switch cipherSuite {
	case CIPHER_COSE_AES128_CBC, CIPHER_COSE_AES128_CTR, CIPHER_COSE_AES256_CBC, CIPHER_COSE_AES256_CTR:
		return decryptETM(encryptedPayload, sessionKeyInfo, cipherSuite)
	case CIPHER_A128GCM, CIPHER_A256GCM:
		return decryptEMB(encryptedPayload, sessionKeyInfo, cipherSuite)
	default:
		return nil, fmt.Errorf("Unsupported encryption scheme! %s", cipherSuite)
	}
}