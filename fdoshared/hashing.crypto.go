package fdoshared

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
)

type HashType int

const (
	FDO_SHA256      HashType = -16
	FDO_SHA384      HashType = -43
	FDO_HMAC_SHA256 HashType = 5
	FDO_HMAC_SHA384 HashType = 6
)

type HashOrHmac struct {
	_    struct{} `cbor:",toarray"`
	Type HashType
	Hash []byte
}

var HmacToHashAlg map[HashType]HashType = map[HashType]HashType{
	FDO_HMAC_SHA256: FDO_SHA256,
	FDO_HMAC_SHA384: FDO_SHA384,
}

func GenerateFdoHash(data []byte, hashType HashType) (HashOrHmac, error) {
	switch hashType {
	case FDO_SHA256:
		hashDigest := sha256.Sum256(data)

		return HashOrHmac{
			Type: hashType,
			Hash: hashDigest[:],
		}, nil
	case FDO_SHA384:
		hashDigest := sha512.Sum384(data)

		return HashOrHmac{
			Type: hashType,
			Hash: hashDigest[:],
		}, nil
	default:
		return HashOrHmac{}, fmt.Errorf("Error generating hash. %d is unknown hashing algorithm", hashType)
	}
}

func GenerateFdoHmac(data []byte, hashType HashType, key []byte) (HashOrHmac, error) {
	switch hashType {
	case FDO_HMAC_SHA256:
		macInst := hmac.New(sha256.New, key)
		macInst.Write(data)

		return HashOrHmac{
			Type: hashType,
			Hash: macInst.Sum(nil),
		}, nil
	case FDO_HMAC_SHA384:
		macInst := hmac.New(sha512.New384, key)
		macInst.Write(data)

		return HashOrHmac{
			Type: hashType,
			Hash: macInst.Sum(nil),
		}, nil
	default:
		return HashOrHmac{}, fmt.Errorf("Error generating hmac. %d is unknown hmac algorithm", hashType)
	}
}

func VerifyHash(data []byte, fdoHashB HashOrHmac) (bool, error) {
	switch fdoHashB.Type {
	case FDO_SHA256:
		if len(fdoHashB.Hash) != sha256.New().Size() {
			return false, errors.New("Failed to verify hash. The input hash does not match expected hash size.")
		}

		fdoHashA, _ := GenerateFdoHash(data, fdoHashB.Type)
		if bytes.Compare(fdoHashB.Hash, fdoHashA.Hash) == 0 {
			return true, nil
		} else {
			return false, nil
		}
	case FDO_SHA384:
		if len(fdoHashB.Hash) != sha512.New384().Size() {
			return false, errors.New("Failed to verify hash. The input hash does not match expected hash size.")
		}

		fdoHashA, _ := GenerateFdoHash(data, fdoHashB.Type)
		if bytes.Compare(fdoHashB.Hash, fdoHashA.Hash) == 0 {
			return true, nil
		} else {
			return false, nil
		}
	default:
		return false, fmt.Errorf("Error verifying hash. %d is an unknown hash algorithm", fdoHashB.Type)
	}
}

func VerifyHMac(data []byte, inputHmac HashOrHmac, key []byte) (bool, error) {
	switch inputHmac.Type {
	case FDO_HMAC_SHA256:
		macInst := hmac.New(sha256.New, key)
		macInst.Write(data)
		computedMac := macInst.Sum(nil)

		if bytes.Compare(inputHmac.Hash, computedMac) == 0 {
			return true, nil
		} else {
			return false, nil
		}
	case FDO_HMAC_SHA384:
		macInst := hmac.New(sha512.New384, key)
		macInst.Write(data)
		computedMac := macInst.Sum(nil)

		if bytes.Compare(inputHmac.Hash, computedMac) == 0 {
			return true, nil
		} else {
			return false, nil
		}
	default:
		return false, fmt.Errorf("Error verifying hmac. %d is unknown hmac algorithm", inputHmac.Type)
	}
}
