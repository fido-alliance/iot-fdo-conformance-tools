package testcom

import (
	"fmt"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func ExpectFdoError(bodyBytes []byte, expectedFdoError fdoshared.FdoErrorCode, httpStatus int) FDOTestState {
	if httpStatus == http.StatusOK {
		return FDOTestState{
			Passed: false,
			Error:  "Expected server to return HTTP error and not status 200 OK",
		}
	}

	fdoErrInst, err := fdoshared.DecodeErrorResponse(bodyBytes)
	if err != nil {
		return FDOTestState{
			Passed: false,
			Error:  "Could not decode FDO Error",
		}
	}

	if fdoErrInst.EMErrorCode != expectedFdoError {
		return FDOTestState{
			Passed: false,
			Error:  fmt.Sprintf("Expected error code %d, got %d", fdoErrInst.EMErrorCode, expectedFdoError),
		}
	}

	return FDOTestState{Passed: true}
}

func ExpectedFdoSuccess(httpStatus int) FDOTestState {
	if httpStatus != http.StatusOK {
		return FDOTestState{
			Passed: false,
			Error:  "Expected server to return 200 OK",
		}
	}

	return FDOTestState{Passed: true}
}

func ExpectGroupTests(testIds []FDOTestID, inputTestId FDOTestID) FDOTestID {
	for _, testId := range testIds {
		if testId == inputTestId {
			return testId
		}
	}

	return FIDO_TEST_GROUP_SKIP
}
