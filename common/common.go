package common

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/fido-alliance/fdo-shared"
	"github.com/fxamacker/cbor/v2"
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

func DecodePemVoucherAndKey(vandvpem string) (*fdoshared.VoucherDBEntry, error) {
	var vandvpemBytes []byte = []byte(vandvpem)

	if len(vandvpem) == 0 {
		return nil, errors.New("Error parsing pem voucher and key. The input is empty")
	}

	voucherBlock, rest := pem.Decode(vandvpemBytes)
	if voucherBlock == nil {
		return nil, errors.New("Could not find voucher PEM data!")
	}

	if voucherBlock.Type != fdoshared.OWNERSHIP_VOUCHER_PEM_TYPE {
		return nil, fmt.Errorf("Failed to decode PEM voucher. Unexpected type: %s", voucherBlock.Type)
	}

	privateKeyBytes, rest := pem.Decode(rest)
	if privateKeyBytes == nil {
		return nil, errors.New("Could not find key PEM data!")
	}

	// CBOR decode voucher

	var voucherInst fdoshared.OwnershipVoucher
	err := cbor.Unmarshal(voucherBlock.Bytes, &voucherInst)
	if err != nil {
		return nil, fmt.Errorf("Could not CBOR unmarshal voucher! %s", err.Error())
	}

	err = voucherInst.Validate()
	if err != nil {
		return nil, fmt.Errorf("Could not validate voucher inst! %s", err.Error())
	}

	return &fdoshared.VoucherDBEntry{
		Voucher:        voucherInst,
		PrivateKeyX509: privateKeyBytes.Bytes,
	}, nil
}
