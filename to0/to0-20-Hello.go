package to0

import (
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"

	"github.com/fxamacker/cbor/v2"
)

func (h *To0Requestor) Hello20(fdoTestID testcom.FDOTestID) (*fdoshared.HelloAck21, error) {
	hello20Bytes, err := cbor.Marshal(fdoshared.Hello20{})
	if err != nil {
		return nil, errors.New("Hell20: Error marshaling Hello20. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO0_20_HELLO, hello20Bytes, &h.rvEntry.AccessToken)
	if err != nil {
		return nil, errors.New("Hell20: " + err.Error())
	}

	h.authzHeader = authzHeader

	var helloAck21 fdoshared.HelloAck21
	err = cbor.Unmarshal(resultBytes, &helloAck21)
	if err != nil {
		return nil, errors.New("Hell20: Failed to unmarshal HelloAck21. " + err.Error())
	}

	return &helloAck21, nil
}
