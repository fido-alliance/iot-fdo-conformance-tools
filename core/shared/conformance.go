package fdoshared

import (
	"fmt"

	lorem "github.com/drhodes/golorem"
	"github.com/fxamacker/cbor/v2"
)

// CONFORMANCE TESTING
func Conf_NewRandomSgTypeExcept(exceptSg DeviceSgType) DeviceSgType {
	for {
		randLoc := NewRandomInt(0, len(DeviceSgTypeList)-1)

		if DeviceSgTypeList[randLoc] != exceptSg {
			return DeviceSgTypeList[randLoc]
		}
	}
}

func Conf_NewRandomHashHmacAlgExcept(exceptHashAlg HashType) HashType {
	for {
		randLoc := NewRandomInt(0, len(HashHmacAlgs)-1)

		if HashHmacAlgs[randLoc] != exceptHashAlg {
			return HashHmacAlgs[randLoc]
		}
	}
}

func Conf_NewRandomFdoPkTypeExcept(exceptAlg FdoPkType) FdoPkType {
	for {
		randLoc := NewRandomInt(0, len(FdoPkType_List)-1)

		if FdoPkType_List[randLoc] != exceptAlg {
			return FdoPkType_List[randLoc]
		}
	}
}

func Conf_NewRandomFdoPkEncExcept(exceptAlg FdoPkEnc) FdoPkEnc {
	for {
		randLoc := NewRandomInt(0, len(FdoPkEnc_List)-1)

		if FdoPkEnc_List[randLoc] != exceptAlg {
			return FdoPkEnc_List[randLoc]
		}
	}
}

func Conf_RandomTestHashHmac(hashHmac HashOrHmac, originalPayload []byte, originalMasterSecret []byte) *HashOrHmac {
	newHashHmac := HashOrHmac{
		Type: hashHmac.Type,
		Hash: hashHmac.Hash,
	}

	randomNumber := NewRandomInt(0, 150)
	if randomNumber < 50 {
		newHashHmac.Hash = NewRandomBuffer(len(newHashHmac.Hash))
	} else if randomNumber > 100 {
		newHashHmac.Type = Conf_NewRandomHashHmacAlgExcept(newHashHmac.Type)
	} else {
		switch newHashHmac.Type {
		case HASH_SHA256, HASH_SHA384:
			if newHashHmac.Type == HASH_SHA256 {
				newHashHmac, _ = GenerateFdoHash(originalPayload, HASH_SHA384)
			} else {
				newHashHmac, _ = GenerateFdoHash(originalPayload, HASH_SHA256)
			}

		case HASH_HMAC_SHA256, HASH_HMAC_SHA384:
			if newHashHmac.Type == HASH_SHA256 {
				newHashHmac, _ = GenerateFdoHash(originalPayload, HASH_HMAC_SHA384)
			} else {
				newHashHmac, _ = GenerateFdoHash(originalPayload, HASH_HMAC_SHA256)
			}
		}
	}

	return &newHashHmac
}

type Conf_CborTypes string

const (
	Conf_CType_String    Conf_CborTypes = "string"
	Conf_CType_Number    Conf_CborTypes = "number"
	Conf_CType_Map       Conf_CborTypes = "map"
	Conf_CType_Array     Conf_CborTypes = "array"
	Conf_CType_ByteArray Conf_CborTypes = "[]byte"
)

var Conf_CborTypes_List []Conf_CborTypes = []Conf_CborTypes{
	Conf_CType_String,
	Conf_CType_Number,
	Conf_CType_Map,
	Conf_CType_Array,
	Conf_CType_ByteArray,
}

func Conf_RandomTypeExcept(exceptType *Conf_CborTypes) interface{} {
	var chosenType Conf_CborTypes
	for {
		randLoc := NewRandomInt(0, len(Conf_CborTypes_List)-1)

		if exceptType == nil || Conf_CborTypes_List[randLoc] != *exceptType {
			chosenType = Conf_CborTypes_List[randLoc]
			break
		}
	}

	switch chosenType {
	case Conf_CType_String:
		return lorem.Word(1, 50)
	case Conf_CType_Number:
		return NewRandomInt(0, 61904)
	case Conf_CType_Map:
		return map[string]interface{}{
			lorem.Word(1, 2): Conf_RandomTypeExcept(nil),
		}
	case Conf_CType_Array:
		return []interface{}{
			Conf_RandomTypeExcept(nil),
			Conf_RandomTypeExcept(nil),
		}
	case Conf_CType_ByteArray:
		return NewRandomBuffer(NewRandomInt(NewRandomInt(0, 51), NewRandomInt(51, 215)))
	default:
		return NewRandomInt(0, 61904)
	}
}

func Conf_RandomTestFuzzPublicKey(pubKey FdoPublicKey) *FdoPublicKey {
	newPubKey := FdoPublicKey{
		PkType: pubKey.PkType,
		PkEnc:  pubKey.PkEnc,
		PkBody: pubKey.PkBody,
	}

	randomNumber := NewRandomInt(0, 150)
	if randomNumber < 50 {
		newPubKey.PkBody = Conf_RandomTypeExcept(nil)
	} else if randomNumber < 100 {
		newPubKey.PkEnc = Conf_NewRandomFdoPkEncExcept(newPubKey.PkEnc)
	} else {
		newPubKey.PkType = Conf_NewRandomFdoPkTypeExcept(newPubKey.PkType)
	}

	return &newPubKey
}

func Conf_RandomCborBufferFuzzing(inputBuff []byte) []byte {
	maxFuzzRange := len(inputBuff) / 3
	actualFuzzRange := maxFuzzRange / 2

	newRandomBuffLength := NewRandomInt(maxFuzzRange-actualFuzzRange, maxFuzzRange)

	var newBuffer []byte = make([]byte, len(inputBuff))
	copy(newBuffer, NewRandomBuffer(newRandomBuffLength))

	return newBuffer
}

func Conf_RandomTestFuzzSigInfo(sigInfo SigInfo) SigInfo {
	newSigInfo := SigInfo{
		SgType: sigInfo.SgType,
		Info:   sigInfo.Info,
	}

	randomNumber := NewRandomInt(0, 100)
	if randomNumber < 50 {
		newSigInfo.SgType = DeviceSgType(NewRandomInt(12, 6312))
	} else {
		newSigInfo.Info = []byte{}
	}

	return newSigInfo
}

type Conf_EncFuzzTypes string

const (
	Conf_EncFuzz_Payload    Conf_EncFuzzTypes = "payload"
	Conf_EncFuzz_Tag        Conf_EncFuzzTypes = "tag"
	Conf_EncFuzz_Ciphertext Conf_EncFuzzTypes = "ciphertext"
	Conf_EncFuzz_IV         Conf_EncFuzzTypes = "iv"
	Conf_EncFuzz_Output     Conf_EncFuzzTypes = "output"
)

var Conf_EncFuzzTypes_List_ETM []Conf_EncFuzzTypes = []Conf_EncFuzzTypes{
	Conf_EncFuzz_Payload,
	Conf_EncFuzz_Tag,
	Conf_EncFuzz_Ciphertext,
	Conf_EncFuzz_IV,
	Conf_EncFuzz_Output,
}

var Conf_EncFuzzTypes_List_EMB []Conf_EncFuzzTypes = []Conf_EncFuzzTypes{
	Conf_EncFuzz_Ciphertext,
	Conf_EncFuzz_IV,
	Conf_EncFuzz_Output,
}

func Conf_Fuzz_AddWrapping(payload []byte, sessionKeyInfo SessionKeyInfo, cipherSuite CipherSuiteName) ([]byte, error) {
	var encryptedBytes []byte
	var err error

	switch cipherSuite {
	case CIPHER_COSE_AES128_CBC, CIPHER_COSE_AES128_CTR, CIPHER_COSE_AES256_CBC, CIPHER_COSE_AES256_CTR:
		var chosenType Conf_EncFuzzTypes = Conf_EncFuzzTypes_List_ETM[NewRandomInt(0, len(Conf_EncFuzzTypes_List_ETM)-1)]

		encryptedBytes, err = encryptETM(payload, sessionKeyInfo, cipherSuite)
		if err != nil {
			return encryptedBytes, err
		}

		var outerBlock ETMOuterBlock
		cbor.Unmarshal(encryptedBytes, &outerBlock)

		var innerBlock ETMInnerBlock
		cbor.Unmarshal(outerBlock.Payload, &innerBlock)

		if chosenType == Conf_EncFuzz_Payload {
			outerBlock.Payload = Conf_RandomCborBufferFuzzing(outerBlock.Payload)
		}

		if chosenType == Conf_EncFuzz_Tag {
			outerBlock.Tag = Conf_RandomCborBufferFuzzing(outerBlock.Tag)
		}

		if chosenType == Conf_EncFuzz_Ciphertext {
			innerBlock.Ciphertext = Conf_RandomCborBufferFuzzing(innerBlock.Ciphertext)
			innerBytes, _ := cbor.Marshal(innerBlock)
			outerBlock.Payload = innerBytes
		}

		if chosenType == Conf_EncFuzz_IV {
			innerBlock.Unprotected.AESIV = NewRandomBuffer(len(innerBlock.Unprotected.AESIV))
			innerBytes, _ := cbor.Marshal(innerBlock)
			outerBlock.Payload = innerBytes
		}

		encryptedBytes, err = cbor.Marshal(outerBlock)

		if chosenType == Conf_EncFuzz_Output {
			encryptedBytes = Conf_RandomCborBufferFuzzing(encryptedBytes)
		}

	case CIPHER_A128GCM, CIPHER_A256GCM:
		var chosenType Conf_EncFuzzTypes = Conf_EncFuzzTypes_List_EMB[NewRandomInt(0, len(Conf_EncFuzzTypes_List_EMB)-1)]

		encryptedBytes, err = encryptEMB(payload, sessionKeyInfo, cipherSuite)
		if err != nil {
			return encryptedBytes, err
		}

		var embBlock EMBlock
		cbor.Unmarshal(encryptedBytes, &embBlock)

		if chosenType == Conf_EncFuzz_Ciphertext {
			embBlock.Ciphertext = Conf_RandomCborBufferFuzzing(embBlock.Ciphertext)
		}

		if chosenType == Conf_EncFuzz_IV {
			embBlock.Unprotected.AESIV = NewRandomBuffer(len(embBlock.Unprotected.AESIV))
		}

		encryptedBytes, err = cbor.Marshal(embBlock)

		if chosenType == Conf_EncFuzz_Output {
			encryptedBytes = Conf_RandomCborBufferFuzzing(encryptedBytes)
		}

	default:
		return nil, fmt.Errorf("unsupported encryption scheme! %d", cipherSuite)
	}

	return encryptedBytes, err
}

type Conf_CoseSign_Field string

const (
	Conf_CoseSign_Field_Protected   Conf_CoseSign_Field = "string"
	Conf_CoseSign_Field_Unprotected Conf_CoseSign_Field = "number"
	Conf_CoseSign_Field_Payload     Conf_CoseSign_Field = "map"
	Conf_CoseSign_Field_Signature   Conf_CoseSign_Field = "array"
)

var Conf_CoseSign_Field_List []Conf_CoseSign_Field = []Conf_CoseSign_Field{
	Conf_CoseSign_Field_Protected,
	Conf_CoseSign_Field_Unprotected,
	Conf_CoseSign_Field_Payload,
	Conf_CoseSign_Field_Signature,
}

func Conf_Fuzz_CoseSignature(coseSignature CoseSignature) CoseSignature {

	var chosenType Conf_CoseSign_Field = Conf_CoseSign_Field_List[NewRandomInt(0, len(Conf_CoseSign_Field_List)-1)]

	switch chosenType {
	case Conf_CoseSign_Field_Protected:
		coseSignature.Protected = NewRandomBuffer(NewRandomInt(5, 49))
	case Conf_CoseSign_Field_Unprotected:
		coseSignature.Unprotected = UnprotectedHeader{}
	case Conf_CoseSign_Field_Payload:
		coseSignature.Payload = Conf_RandomCborBufferFuzzing(coseSignature.Payload)
	default:
		coseSignature.Signature = Conf_RandomCborBufferFuzzing(coseSignature.Signature)
	}

	return coseSignature
}
