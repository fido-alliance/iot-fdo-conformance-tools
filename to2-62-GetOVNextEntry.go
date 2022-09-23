package fdodeviceimplementation

import (
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *To2Requestor) GetOVNextEntry62(entryNum uint8, fdoTestID testcom.FDOTestID) (*fdoshared.OVNextEntry63, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	getOVNextEntry := fdoshared.GetOVNextEntry62{
		GetOVNextEntry: entryNum,
	}

	getOvNextEntryBytes, _ := cbor.Marshal(getOVNextEntry)

	if fdoTestID == testcom.FIDO_DOT_62_BAD_ENCODING {
		getOvNextEntryBytes = fdoshared.Conf_RandomCborBufferFuzzing(getOvNextEntryBytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(h.SrvEntry, fdoshared.TO2_62_GET_OVNEXTENTRY, getOvNextEntryBytes, &h.AuthzHeader)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
	}

	if err != nil {
		return nil, nil, err
	}

	h.AuthzHeader = authzHeader

	var nextEntry fdoshared.OVNextEntry63
	err = cbor.Unmarshal(resultBytes, &nextEntry)
	if err != nil {
		return nil, nil, errors.New("GetOVNextEntry64: Failed to unmarshal OVNextEntry63. " + err.Error())
	}

	return &nextEntry, &testState, nil
}
