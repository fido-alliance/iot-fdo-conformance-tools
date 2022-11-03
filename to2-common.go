package fdodeviceimplementation

import (
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

var MaxDeviceMessageSize uint16 = 2048
var MaxOwnerServiceInfoSize uint16 = 2048

type To2Requestor struct {
	SrvEntry        SRVEntry
	Credential      fdoshared.WawDeviceCredential
	KexSuiteName    fdoshared.KexSuiteName
	CipherSuiteName fdoshared.CipherSuiteName

	AuthzHeader string
	SessionKey  fdoshared.SessionKeyInfo
	XAKex       []byte
	XBKEXParams fdoshared.KeXParams

	NonceTO2ProveOV60 fdoshared.FdoNonce
	NonceTO2ProveDv61 fdoshared.FdoNonce
	NonceTO2SetupDv64 fdoshared.FdoNonce

	ProveOVHdr61PubKey fdoshared.FdoPublicKey
	OvHmac             fdoshared.HashOrHmac

	Completed60 bool
	Completed62 bool
	Completed64 bool
}

func NewTo2Requestor(srvEntry SRVEntry, credential fdoshared.WawDeviceCredential, kexSuitName fdoshared.KexSuiteName, cipherSuitName fdoshared.CipherSuiteName) To2Requestor {
	return To2Requestor{
		SrvEntry:        srvEntry,
		Credential:      credential,
		KexSuiteName:    kexSuitName,
		CipherSuiteName: cipherSuitName,
	}
}

func (h *To2Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_30, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_32, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	}
	return testcom.FDOTestState{
		Passed: false,
		Error:  "Unsupported test " + string(fdoTestID),
	}
}
