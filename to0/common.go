package to0

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
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
