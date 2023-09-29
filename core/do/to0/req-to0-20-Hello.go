package to0

import (
	"errors"
	"fmt"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

func (h *To0Requestor) Hello20(fdoTestID testcom.FDOTestID) (*fdoshared.HelloAck21, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState
	var helloAck21 fdoshared.HelloAck21

	hello20Bytes, err := fdoshared.CborCust.Marshal(fdoshared.Hello20{})
	if err != nil {
		return nil, nil, errors.New("Hell20: Error marshaling Hello20. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_RVT_20_BAD_ENCODING {
		hello20Bytes = fdoshared.Conf_RandomCborBufferFuzzing(hello20Bytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(fdoTestID, h.rvEntry, fdoshared.TO0_20_HELLO, hello20Bytes, &h.rvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("Hell20: Error sending RV request: " + err.Error())
	}

	h.authzHeader = authzHeader

	fdoErrInst, err := fdoshared.DecodeErrorResponse(resultBytes)
	if err == nil {
		return nil, nil, fmt.Errorf("Server returned FDO error: %s %d", fdoErrInst.EMErrorStr, fdoErrInst.EMErrorCode)
	}

	err = fdoshared.CborCust.Unmarshal(resultBytes, &helloAck21)
	if err != nil {
		return nil, nil, errors.New("Hell20: Failed to unmarshal HelloAck21. " + err.Error())
	}

	return &helloAck21, &testState, nil
}
