package to0

import (
	"errors"
	"fmt"
	"log"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

func (h *To0Requestor) OwnerSign22(nonceTO0Sign fdoshared.FdoNonce, fdoTestId testcom.FDOTestID) (*fdoshared.AcceptOwner23, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState
	var acceptOwner23 fdoshared.AcceptOwner23

	var to0d fdoshared.To0d = fdoshared.To0d{
		OwnershipVoucher: h.voucherDBEntry.Voucher,
		WaitSeconds:      ServerWaitSeconds,
		NonceTO0Sign:     nonceTO0Sign,
	}

	if fdoTestId == testcom.FIDO_RVT_22_BAD_TO0SIGN_NONCE {
		to0d.NonceTO0Sign = fdoshared.NewFdoNonce()
	}

	to0dBytes, err := fdoshared.CborCust.Marshal(to0d)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error marshaling To0d. " + err.Error())
	}

	if fdoTestId == testcom.FIDO_RVT_22_BAD_TO0D_ENCODING {
		to0dBytes = fdoshared.Conf_RandomCborBufferFuzzing(to0dBytes)
	}

	deviceHashAlg := fdoshared.HmacToHashAlg[h.voucherDBEntry.Voucher.OVHeaderHMac.Type]
	to0dHash, err := fdoshared.GenerateFdoHash(to0dBytes, deviceHashAlg)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error generating to0dHash. " + err.Error())
	}

	if fdoTestId == testcom.FIDO_RVT_22_BAD_TO0D_HASH {
		to0dHash = *fdoshared.Conf_RandomTestHashHmac(to0dHash, to0dBytes, []byte{})
	}

	// TO1D Payload
	// TODO
	var localostIPBytes fdoshared.FdoIPAddress = []byte{127, 0, 0, 1}

	var to1dPayload fdoshared.To1dBlobPayload = fdoshared.To1dBlobPayload{
		To1dRV: []fdoshared.RVTO2AddrEntry{
			{
				RVIP:       &localostIPBytes,
				RVPort:     8080,
				RVProtocol: fdoshared.ProtHTTP,
			},
		},
		To1dTo0dHash: to0dHash,
	}

	to1dPayloadBytes, err := fdoshared.CborCust.Marshal(to1dPayload)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error marshaling To1dPayload. " + err.Error())
	}

	// TO1D CoseSignature

	var lastOvEntryPubKeyPkType fdoshared.FdoPkType = fdoshared.SECP256R1
	if fdoTestId != testcom.FIDO_TEST_VOUCHER_BAD_EMPTY_ENTRIES {
		lastOvEntryPubKey, err := h.voucherDBEntry.Voucher.GetFinalOwnerPublicKey()
		if err != nil {
			return nil, nil, errors.New("OwnerSign22: Error extracting last OVEntry public key. " + err.Error())
		}

		lastOvEntryPubKeyPkType = lastOvEntryPubKey.PkType
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.voucherDBEntry.PrivateKeyX509)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error extracting private key. " + err.Error())
	}

	sgType, err := fdoshared.GetDeviceSgType(lastOvEntryPubKeyPkType, deviceHashAlg)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error getting device SgType. " + err.Error())
	}

	to1d, err := fdoshared.GenerateCoseSignature(to1dPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, sgType)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error generating To1D COSE signature. " + err.Error())
	}

	if fdoTestId == testcom.FIDO_RVT_22_BAD_SIGNATURE {
		to1d.Signature = fdoshared.Conf_RandomCborBufferFuzzing(to1d.Signature)
	}

	var ownerSign fdoshared.OwnerSign22 = fdoshared.OwnerSign22{
		To0d: to0dBytes,
		To1d: *to1d,
	}

	ownerSign22Bytes, err := fdoshared.CborCust.Marshal(ownerSign)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Error marshaling OwnerSign22. " + err.Error())
	}

	if fdoTestId == testcom.FIDO_RVT_22_BAD_OWNERSIGN_ENCODING {
		ownerSign22Bytes = fdoshared.Conf_RandomCborBufferFuzzing(ownerSign22Bytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(fdoTestId, h.rvEntry, fdoshared.TO0_22_OWNER_SIGN, ownerSign22Bytes, &h.authzHeader)
	if fdoTestId != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestId, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("OwnerSign22: " + err.Error())
	}

	h.authzHeader = authzHeader

	fdoErrInst, err := fdoshared.DecodeErrorResponse(resultBytes)
	if err == nil {
		return nil, nil, fmt.Errorf("server returned FDO error: %s %d", fdoErrInst.EMErrorStr, fdoErrInst.EMErrorCode)
	}

	err = fdoshared.CborCust.Unmarshal(resultBytes, &acceptOwner23)
	if err != nil {
		return nil, nil, errors.New("OwnerSign22: Failed to unmarshal AcceptOwner23. " + err.Error())
	}

	voucherHeader, _ := h.voucherDBEntry.Voucher.GetOVHeader()
	if fdoTestId == testcom.NULL_TEST && h.ctx.Value(fdoshared.CFG_ENV_INTEROP_ENABLED).(bool) {
		authzHeader, err := fdoshared.IopGetAuthz(h.ctx, fdoshared.IopDO)
		if err != nil {
			log.Println("IOT: Error getting authz header: " + err.Error())
		}

		err = fdoshared.SubmitIopLoggerEvent(h.ctx, voucherHeader.OVGuid, fdoshared.To0, nonceTO0Sign, authzHeader)
		if err != nil {
			log.Println("IOT: Error sending iop logg event: " + err.Error())
		}
	}

	return &acceptOwner23, &testState, nil
}
