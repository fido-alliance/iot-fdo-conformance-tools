package fdoshared

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type SRVEntry struct { // TODO: Unify type with DO
	SrvURL      string
	AccessToken string // FUTURE
	OverrideURL bool
}

func SendCborPost(rvEntry SRVEntry, cmd FdoCmd, payload []byte, authzHeader *string) ([]byte, string, int, error) {
	address, err := url.Parse(rvEntry.SrvURL)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error joining parsing url %s %s", rvEntry.SrvURL, err.Error())
	}

	address = address.JoinPath(FDO_101_URL_BASE, cmd.ToString())

	if rvEntry.OverrideURL {
		address = address.JoinPath(cmd.ToString())
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("POST", address.String(), bytes.NewBuffer(payload))
	if err != nil {
		return nil, "", 0, errors.New("Error creating new request. " + err.Error())
	}

	if authzHeader != nil {
		req.Header.Set("Authorization", *authzHeader)
	}

	req.Header.Set("Content-Type", "application/cbor")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error sending post request to %s url. %s", address, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Error reading body bytes for %s url. %s", address, err.Error())
	}

	return bodyBytes, resp.Header.Get("Authorization"), resp.StatusCode, nil
}
