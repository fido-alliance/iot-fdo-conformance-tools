package to0

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/WebauthnWorks/fdo-shared/testcom"
	"github.com/fxamacker/cbor/v2"
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

func SendCborPost(rvEntry RVEntry, cmd fdoshared.FdoCmd, payload []byte, authzHeader *string) ([]byte, string, int, error) {
	url := rvEntry.RVURL + fdoshared.FDO_101_URL_BASE + cmd.ToString()

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
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
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error reading body bytes for %s url. %s", url, err.Error())
	}

	return bodyBytes, resp.Header.Get("Authorization"), resp.StatusCode, nil
}

func (h *To0Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {
	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_RVT_20, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.FIDO_RVT_21_CHECK_RESP:
		var helloAck21 fdoshared.HelloAck21
		err := cbor.Unmarshal(bodyBytes, &helloAck21)
		if err != nil {
			return testcom.NewFailTestState(fdoTestID, "Error decoding HelloAck21. "+err.Error())
		}

		return testcom.NewSuccessTestState(fdoTestID)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_RVT_20, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_RVT_22, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_VOUCHER, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoTestID, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)
	}

	return testcom.NewFailTestState(fdoTestID, "Unsupported test "+string(fdoTestID))
}
