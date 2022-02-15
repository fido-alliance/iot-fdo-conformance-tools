package fdoshared

import (
	"math/rand"
	"time"
)

type FdoError struct {
	_           struct{} `cbor:",toarray"`
	EMErrorCode FdoErrorCode
	EMPrevMsgID FdoCmd
	EMErrorStr  string
	EMErrorTs   FdoTimestamp
	EMErrorCID  uint // CorrelationID
}

func NewFdoError(errorCode FdoErrorCode, prevMsgId FdoCmd, messageStr string) FdoError {
	now := time.Now()

	return FdoError{
		EMErrorCode: errorCode,
		EMPrevMsgID: prevMsgId,
		EMErrorStr:  messageStr,
		EMErrorTs:   now.Unix(),
		EMErrorCID:  uint(rand.Uint64()),
	}
}

type FdoErrorCode uint16

const (
	// TO0.OwnerSign, TO1.ProveToRV, TO2.GetOVNextEntry, TO2.ProveDevice, TO2.NextDeviceServiceInfo, TO2.Done
	INVALID_JWT_TOKEN FdoErrorCode = 1

	// TO0.OwnerSign
	INVALID_OWNERSHIP_VOUCHER FdoErrorCode = 2

	// TO0.OwnerSign
	INVALID_OWNER_SIGN_BODY FdoErrorCode = 3

	// TO0.OwnerSign
	INVALID_IP_ADDRESS FdoErrorCode = 4

	// TO0.OwnerSign
	INVALID_GUID FdoErrorCode = 5

	// TO1.HelloRV TO2.HelloDevice
	RESOURCE_NOT_FOUND FdoErrorCode = 6

	// All
	// Message Body is structurally unsound:
	// JSON parse error, or valid JSON, but is not mapping to the expected Secure Device Onboard type (see ‎4.6)
	MESSAGE_BODY_ERROR FdoErrorCode = 100

	// All
	// Message structurally sound, but failed validation tests.
	// The nonce didn’t match, signature didn’t verify, hash, or mac didn’t verify, index out of bounds, etc...
	INVALID_MESSAGE_ERROR FdoErrorCode = 101

	// TO2.SetupDevice
	CRED_REUSE_ERROR FdoErrorCode = 102

	// All
	INTERNAL_SERVER_ERROR FdoErrorCode = 500
)
