package to2

import (
	"errors"
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

func (h *To2Requestor) GetOVNextEntry62(entryNum uint8, fdoTestID testcom.FDOTestID) (*fdoshared.OVNextEntry63, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	getOVNextEntry := fdoshared.GetOVNextEntry62{
		GetOVNextEntry: entryNum,
	}

	getOvNextEntryBytes, _ := fdoshared.CborCust.Marshal(getOVNextEntry)

	if fdoTestID == testcom.FIDO_DOT_62_BAD_ENCODING {
		getOvNextEntryBytes = fdoshared.Conf_RandomCborBufferFuzzing(getOvNextEntryBytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.SrvEntry, fdoshared.TO2_62_GET_OVNEXTENTRY, getOvNextEntryBytes, &h.AuthzHeader)
	if fdoTestID != testcom.NULL_TEST && fdoTestID != testcom.FIDO_DOT_62_POSITIVE {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, err
	}

	if httpStatusCode != http.StatusOK {
		fdoErrInst, err := fdoshared.DecodeErrorResponse(resultBytes)
		if err == nil {
			return nil, nil, fmt.Errorf("GetOVNextEntry62: %s", fdoErrInst.EMErrorStr)
		}
	}

	if authzHeader != "" {
		h.AuthzHeader = authzHeader
	}

	var nextEntry fdoshared.OVNextEntry63
	fdoError, err := fdoshared.TryCborUnmarshal(resultBytes, &nextEntry)
	if err != nil {
		return nil, nil, errors.New("GetOVNextEntry64: Failed to unmarshal OVNextEntry63. " + err.Error())
	}

	if fdoError != nil {
		return nil, nil, errors.New("GetOVNextEntry64: Received FDO Error: " + fdoError.Error())
	}

	return &nextEntry, &testState, nil
}
