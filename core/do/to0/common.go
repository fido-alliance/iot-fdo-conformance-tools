package to0

import (
	"context"
	"fmt"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

type To0Requestor struct {
	srvEntry       fdoshared.SRVEntry
	voucherDBEntry fdoshared.VoucherDBEntry
	authzHeader    string
	ctx            context.Context
}

func NewTo0Requestor(rvEntry fdoshared.SRVEntry, voucherDBEntry fdoshared.VoucherDBEntry, ctx context.Context) To0Requestor {
	return To0Requestor{
		srvEntry:       rvEntry,
		voucherDBEntry: voucherDBEntry,
		ctx:            ctx,
	}
}

const ServerWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

func (h *To0Requestor) getRVTO2AddrEntry() (*fdoshared.RVTO2AddrEntry, error) {
	servUrl := h.ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string)
	if servUrl == "" {
		return nil, fmt.Errorf("getRVTO2AddrEntry: FDO service URL not set")
	}

	return fdoshared.UrlToTOAddrEntry(servUrl)
}

func (h *To0Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	expectedErrorCode, ok := testcom.FIDO_TEST_TO_FDO_ERROR_CODE[fdoTestID]
	if !ok {
		expectedErrorCode = fdoshared.MESSAGE_BODY_ERROR
	}

	switch fdoTestID {
	case testcom.FIDO_RVT_21_CHECK_RESP:
		fdoErrInst, err := fdoshared.DecodeErrorResponse(bodyBytes)
		if err == nil {
			return testcom.NewFailTestState(fdoTestID, fmt.Sprintf("Server returned FDO error: %s %d", fdoErrInst.EMErrorStr, fdoErrInst.EMErrorCode))
		}

		var helloAck21 fdoshared.HelloAck21
		err = fdoshared.CborCust.Unmarshal(bodyBytes, &helloAck21)
		if err != nil {
			return testcom.NewFailTestState(fdoTestID, "Error decoding HelloAck21. "+err.Error())
		}

		return testcom.NewSuccessTestState(fdoTestID)

	case testcom.FIDO_RVT_23_CHECK_RESP:
		fdoErrInst, err := fdoshared.DecodeErrorResponse(bodyBytes)
		if err == nil {
			return testcom.NewFailTestState(fdoTestID, fmt.Sprintf("Server returned FDO error: %s %d", fdoErrInst.EMErrorStr, fdoErrInst.EMErrorCode))
		}

		var acceptOwner fdoshared.AcceptOwner23
		err = fdoshared.CborCust.Unmarshal(bodyBytes, &acceptOwner)
		if err != nil {
			return testcom.NewFailTestState(fdoTestID, "Error decoding AcceptOwner23. "+err.Error())
		}

		return testcom.NewSuccessTestState(fdoTestID)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_RVT_20, fdoTestID):
		return testcom.ExpectAnyFdoError(bodyBytes, fdoTestID, expectedErrorCode, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_RVT_22, fdoTestID):
		return testcom.ExpectAnyFdoError(bodyBytes, fdoTestID, expectedErrorCode, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_VOUCHER, fdoTestID):
		return testcom.ExpectAnyFdoError(bodyBytes, fdoTestID, expectedErrorCode, httpStatusCode)
	}

	return testcom.NewFailTestState(fdoTestID, "Unsupported test "+string(fdoTestID))
}
