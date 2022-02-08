package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

type RVEntry struct {
	RVURL       string
	AccessToken string
}

type To1Requestor struct {
	rvEntry        RVEntry
	voucherDBEntry VoucherDBEntry
	authzHeader    string
}

type VoucherDBEntry struct {
	_              struct{} `cbor:",toarray"`
	Voucher        fdoshared.OwnershipVoucher
	PrivateKeyX509 []byte
}

func NewTo1Requestor(rvEntry RVEntry, voucherDBEntry VoucherDBEntry) To1Requestor {
	return To1Requestor{
		rvEntry:        rvEntry,
		voucherDBEntry: voucherDBEntry,
	}
}

func SendCborPost(rvEntry RVEntry, cmd fdoshared.FdoCmd, payload []byte, authzHeader *string) ([]byte, string, error) {
	url := rvEntry.RVURL + fdoshared.FDO_101_URL_BASE + cmd.ToString()

	httpClient := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, "", errors.New("Error creating new request. " + err.Error())
	}

	if authzHeader != nil {
		req.Header.Set("Authorization", *authzHeader)
	}

	req.Header.Set("Content-Type", "application/cbor")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("Error sending post request to %s url. %s", url, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("Error reading body bytes for %s url. %s", url, err.Error())
	}

	return bodyBytes, resp.Header.Get("Authorization"), nil
}

func (h *To1Requestor) HelloRV30() (*fdoshared.HelloRVAck31, error) {

	// create eASigInfo
	helloRV30Bytes, err := cbor.Marshal(fdoshared.HelloRV30{
		Guid: h.voucherDBEntry.Voucher.FdoGuid,
		EASigInfo: fdoshared.SigInfo{
			SgType: -7,
			Info:   "I am test!",
		},
	})

	if err != nil {
		return nil, errors.New("Hello30: Error marshaling Hello30. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO1_HELLO_RV_30, helloRV30Bytes, &h.rvEntry.AccessToken)
	if err != nil {
		return nil, errors.New("Hello30: " + err.Error())
	}

	h.authzHeader = authzHeader

	var helloRVAck31 fdoshared.HelloRVAck31
	err = cbor.Unmarshal(resultBytes, &helloRVAck31)
	if err != nil {
		return nil, errors.New("HelloRV30: Failed to unmarshal HelloRVAck31. " + err.Error())
	}

	return &helloRVAck31, nil
}

// To1 - todo
func (h *To1Requestor) ProveToRV32(proveToRV32 fdoshared.ProveToRV32) (*fdoshared.RVRedirect33, error) {
	// To1

	proveToRV32Bytes, err := cbor.Marshal(proveToRV32)
	if err != nil {
		return nil, errors.New("ProveToRV32: Error marshaling proveToRV32. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO1_PROVE_TO_RV_32, proveToRV32Bytes, &h.rvEntry.AccessToken)
	if err != nil {
		return nil, errors.New("Hello30: " + err.Error())
	}

	h.authzHeader = authzHeader

	var rvRedirect33 fdoshared.RVRedirect33
	err = cbor.Unmarshal(resultBytes, &rvRedirect33)
	if err != nil {
		return nil, errors.New("RVRedirect33: Failed to unmarshal RVRedirect33. " + err.Error())
	}

	return &rvRedirect33, nil
}

// func SubmitOwnershipVoucherToRv(voucherDbEntry VoucherDBEntry, rvEntry RVEntry) error {

// }
