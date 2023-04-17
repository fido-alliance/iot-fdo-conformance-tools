package testcom

import (
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/fdo-shared"
)

func ExpectFdoError(bodyBytes []byte, testId FDOTestID, expectedFdoError fdoshared.FdoErrorCode, httpStatus int) FDOTestState {
	if httpStatus == http.StatusOK {
		return NewFailTestState(testId, "Server return HTTP 200OK. Expected error.")
	}

	fdoErrInst, err := fdoshared.DecodeErrorResponse(bodyBytes)
	if err != nil {
		return NewFailTestState(testId, "Could not decode FDO Error")
	}

	if fdoErrInst.EMErrorCode != expectedFdoError {
		return NewFailTestState(testId, fmt.Sprintf("Expected error code %d, got %d", expectedFdoError, fdoErrInst.EMErrorCode))
	}

	return NewSuccessTestState(testId)
}

func ExpectAnyFdoError(bodyBytes []byte, testId FDOTestID, expectedFdoError fdoshared.FdoErrorCode, httpStatus int) FDOTestState {
	if httpStatus == http.StatusOK {
		return NewFailTestState(testId, "Server return HTTP 200OK. Expected error.")
	}

	_, err := fdoshared.DecodeErrorResponse(bodyBytes)
	if err != nil {
		return NewFailTestState(testId, "Could not decode FDO Error")
	}

	return NewSuccessTestState(testId)
}

func ExpectedFdoSuccess(testId FDOTestID, httpStatus int) FDOTestState {
	if httpStatus != http.StatusOK {
		return NewFailTestState(testId, fmt.Sprintf("Server return HTTP Error %d. Expected HTTP 200OK", httpStatus))
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
