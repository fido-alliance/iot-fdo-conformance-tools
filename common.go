package fdodeviceimplementation

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

type SRVEntry struct { // TODO: Unify type with DO
	SrvURL      string
	AccessToken string // FUTURE
}

func SendCborPost(rvEntry SRVEntry, cmd fdoshared.FdoCmd, payload []byte, authzHeader *string) ([]byte, string, int, error) {
	url := rvEntry.SrvURL + fdoshared.FDO_101_URL_BASE + cmd.ToString()

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
