package to0

import (
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"

	"github.com/fxamacker/cbor/v2"
)

func (h *To0Requestor) checkHello20Response(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {
	case testcom.FIDO_RVT_20_BAD_ENCODING:
		return testcom.ExpectFdoError(bodyBytes, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.FIDO_RVT_21_CHECK_RESP:
		var helloAck21 fdoshared.HelloAck21
		err := cbor.Unmarshal(bodyBytes, &helloAck21)
		if err != nil {
			return testcom.FDOTestState{
				Passed: false,
				Error:  "Error decoding HelloAck21. " + err.Error(),
			}
		}

		return testcom.FDOTestState{Passed: true}
	}

	return testcom.FDOTestState{
		Passed: false,
		Error:  "Unsupported test " + string(fdoTestID),
	}
}

func (h *To0Requestor) Hello20(fdoTestID testcom.FDOTestID) (*fdoshared.HelloAck21, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState
	var helloAck21 fdoshared.HelloAck21

	hello20Bytes, err := cbor.Marshal(fdoshared.Hello20{})
	if err != nil {
		return nil, nil, errors.New("Hell20: Error marshaling Hello20. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_RVT_20_BAD_ENCODING {
		hello20Bytes[0] = 0x42
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(h.rvEntry, fdoshared.TO0_20_HELLO, hello20Bytes, &h.rvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.checkHello20Response(resultBytes, fdoTestID, httpStatusCode)
		return &helloAck21, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("Hell20: " + err.Error())
	}

	h.authzHeader = authzHeader

	err = cbor.Unmarshal(resultBytes, &helloAck21)
	if err != nil {
		return nil, nil, errors.New("Hell20: Failed to unmarshal HelloAck21. " + err.Error())
	}

	return &helloAck21, &testState, nil
}
