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

// To0D0
func (h *To1Requestor) ProveToRV32(nonceTO0Sign []byte) (*fdoshared.RVRedirect33, error) {
	// TO0D
	var to0d fdoshared.To0d = fdoshared.To0d{
		OwnershipVoucher: h.voucherDBEntry.Voucher,
		WaitSeconds:      10,
		NonceTO0Sign:     nonceTO0Sign,
	}
	to0dBytes, err := cbor.Marshal(to0d)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling To0d. " + err.Error())
	}

	deviceHashAlg := fdoshared.HmacToHashAlg[h.voucherDBEntry.Voucher.OVHeaderHMac.Type]
	to0dHash, err := fdoshared.GenerateFdoHash(to0dBytes, deviceHashAlg)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error generating to0dHash. " + err.Error())
	}

	// TO1D Payload
	// TODO
	var localostIPBytes fdoshared.FdoIPAddress = []byte{127, 0, 0, 1}

	var to1dPayload fdoshared.To1dBlobPayload = fdoshared.To1dBlobPayload{
		To1dRV: []fdoshared.RVTO2AddrEntry{
			{
				RVIP:       &localostIPBytes,
				RVPort:     8084,
				RVProtocol: fdoshared.ProtHTTP,
			},
		},
		To1dTo0dHash: to0dHash,
	}

	to1dPayloadBytes, err := cbor.Marshal(to1dPayload)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling To1dPayload. " + err.Error())
	}

	// TO1D CoseSignature
	lastOvEntryPubKey, err := h.voucherDBEntry.Voucher.GetFinalOwnerPublicKey()
	if err != nil {
		return nil, errors.New("OwnerSign22: Error extracting last OVEntry public key. " + err.Error())
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.voucherDBEntry.PrivateKeyX509)

	sgType, err := fdoshared.GetDeviceSgType(lastOvEntryPubKey.PkType, deviceHashAlg)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error getting device SgType. " + err.Error())
	}

	to1d, err := fdoshared.GenerateCoseSignature(to1dPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, sgType)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error generating To1D COSE signature. " + err.Error())
	}

	var ownerSign fdoshared.OwnerSign22 = fdoshared.OwnerSign22{
		To0d: to0dBytes,
		To1d: *to1d,
	}
	ownerSign22Bytes, err := cbor.Marshal(ownerSign)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling OwnerSign22. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO0_OWNER_SIGN_22, ownerSign22Bytes, &h.authzHeader)
	if err != nil {
		return nil, errors.New("OwnerSign22: " + err.Error())
	}

	h.authzHeader = authzHeader

	var acceptOwner23 fdoshared.AcceptOwner23
	err = cbor.Unmarshal(resultBytes, &acceptOwner23)
	if err != nil {
		return nil, errors.New("OwnerSign22: Failed to unmarshal AcceptOwner23. " + err.Error())
	}

	return &acceptOwner23, nil
}

// func SubmitOwnershipVoucherToRv(voucherDbEntry VoucherDBEntry, rvEntry RVEntry) error {

// }
