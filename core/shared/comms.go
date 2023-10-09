package fdoshared

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type SRVEntry struct { // TODO: Unify type with DO
	SrvURL      string
	AccessToken string // FUTURE
	OverrideURL bool
}

func SendCborPost(rvEntry SRVEntry, cmd FdoCmd, payload []byte, authzHeader *string) ([]byte, string, int, error) {
	url := rvEntry.SrvURL + FDO_101_URL_BASE + cmd.ToString()

	if rvEntry.OverrideURL {
		url = rvEntry.SrvURL + cmd.ToString()
	}

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
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error reading body bytes for %s url. %s", url, err.Error())
	}

	return bodyBytes, resp.Header.Get("Authorization"), resp.StatusCode, nil
}
