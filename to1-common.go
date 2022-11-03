package fdodeviceimplementation

import (
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

type To1Requestor struct {
	rvEntry     SRVEntry
	credential  fdoshared.WawDeviceCredential
	authzHeader string
}

func NewTo1Requestor(srvEntry SRVEntry, credential fdoshared.WawDeviceCredential) To1Requestor {
	return To1Requestor{
		rvEntry:    srvEntry,
		credential: credential,
	}
}

func (h *To1Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_30, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_32, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	}
	return testcom.NewFailTestState(fdoTestID, "Unsupported test "+string(fdoTestID))
}
