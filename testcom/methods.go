package testcom

import (
	"fmt"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func ExpectFdoError(bodyBytes []byte, testId FDOTestID, expectedFdoError fdoshared.FdoErrorCode, httpStatus int) FDOTestState {
	if httpStatus == http.StatusOK {
		return NewFailTestState(testId, "Expected server to return HTTP error, and not status 200 OK")
	}

	fdoErrInst, err := fdoshared.DecodeErrorResponse(bodyBytes)
	if err != nil {
		return NewFailTestState(testId, "Could not decode FDO Error")
	}

	if fdoErrInst.EMErrorCode != expectedFdoError {
		return NewFailTestState(testId, fmt.Sprintf("Expected error code %d, got %d", fdoErrInst.EMErrorCode, expectedFdoError))
	}

	return NewSuccessTestState(testId)
}

func ExpectedFdoSuccess(testId FDOTestID, httpStatus int) FDOTestState {
	if httpStatus != http.StatusOK {
		return NewFailTestState(testId, "Expected server to return 200 OK")
	}

	return NewSuccessTestState(testId)
}

func ExpectGroupTests(testIds []FDOTestID, inputTestId FDOTestID) FDOTestID {
	for _, testId := range testIds {
		if testId == inputTestId {
			return testId
		}
	}

	return FIDO_TEST_GROUP_SKIP
}
