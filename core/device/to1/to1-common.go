package to1

import (
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

type To1Requestor struct {
	rvEntry     fdoshared.SRVEntry
	credential  fdoshared.WawDeviceCredential
	authzHeader string
}

func NewTo1Requestor(srvEntry fdoshared.SRVEntry, credential fdoshared.WawDeviceCredential) To1Requestor {
	return To1Requestor{
		rvEntry:    srvEntry,
		credential: credential,
	}
}

func (h *To1Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_30, fdoTestID):
		return testcom.ExpectAnyFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_32, fdoTestID):
		return testcom.ExpectAnyFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	}
	return testcom.NewFailTestState(fdoTestID, "Unsupported test "+string(fdoTestID))
}
