package fdodeviceimplementation

import (
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *To2Requestor) GetOVNextEntry62(entryNum uint8, fdoTestID testcom.FDOTestID) (*fdoshared.OVNextEntry63, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	getOvNextEntryBytes, _ := cbor.Marshal(fdoshared.GetOVNextEntry62{
		GetOVNextEntry: entryNum,
	})

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
