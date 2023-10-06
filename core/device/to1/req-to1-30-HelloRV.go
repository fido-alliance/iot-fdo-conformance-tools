package to1

import (
	"errors"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

func (h *To1Requestor) HelloRV30(fdoTestID testcom.FDOTestID) (*fdoshared.HelloRVAck31, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState
	var helloRVAck31 fdoshared.HelloRVAck31

	helloRv30 := fdoshared.HelloRV30{
		Guid:      h.credential.DCGuid,
		EASigInfo: h.credential.DCSigInfo,
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_UNKNOWN_GUID {
		helloRv30.Guid = fdoshared.NewFdoGuid()
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_SIGINFO {
		helloRv30.EASigInfo = fdoshared.Conf_RandomTestFuzzSigInfo(helloRv30.EASigInfo)
	}

	helloRV30Bytes, err := fdoshared.CborCust.Marshal(helloRv30)
	if err != nil {
		return nil, nil, errors.New("HelloRV30: Error marshaling HelloRV30. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_ENCODING {
		helloRV30Bytes = fdoshared.Conf_RandomCborBufferFuzzing(helloRV30Bytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.rvEntry, fdoshared.TO1_30_HELLO_RV, helloRV30Bytes, &h.rvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
	}

	if err != nil {
		return nil, &testState, errors.New("HelloRV30: Error sending RV request: " + err.Error())
	}

	h.authzHeader = authzHeader

	err = fdoshared.CborCust.Unmarshal(resultBytes, &helloRVAck31)
	if err != nil {
		return nil, &testState, errors.New("HelloRV30: Failed to unmarshal HelloRvAck31. " + err.Error())
	}

	return &helloRVAck31, &testState, nil
}
