package to0

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

type To0Requestor struct {
	rvEntry        RVEntry
	voucherDBEntry fdoshared.VoucherDBEntry
	authzHeader    string
}

func NewTo0Requestor(rvEntry RVEntry, voucherDBEntry fdoshared.VoucherDBEntry) To0Requestor {
	return To0Requestor{
		rvEntry:        rvEntry,
		voucherDBEntry: voucherDBEntry,
	}
}

const ServerWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type RVEntry struct {
	RVURL       string
	AccessToken string
}

func SendCborPost(fdoTestID testcom.FDOTestID, rvEntry RVEntry, cmd fdoshared.FdoCmd, payload []byte, authzHeader *string) ([]byte, string, int, error) {
	url := rvEntry.RVURL + fdoshared.FDO_101_URL_BASE + cmd.ToString()

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	log.Printf("--- %d %s. Sending buffer %s", cmd, fdoTestID, hex.EncodeToString(payload))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, "", 0, errors.New("Error creating new request. " + err.Error())
	}

	if authzHeader != nil {
		req.Header.Set("Authorization", *authzHeader)
	}

	req.Header.Set("Content-Type", "application/cbor")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error sending post request to %s url. %s", url, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error reading body bytes for %s url. %s", url, err.Error())
	}
	log.Printf("--- %d %s. HTTP %d Receiving buffer %s \n\n", cmd, fdoTestID, resp.StatusCode, hex.EncodeToString(bodyBytes))

	return bodyBytes, resp.Header.Get("Authorization"), resp.StatusCode, nil
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
