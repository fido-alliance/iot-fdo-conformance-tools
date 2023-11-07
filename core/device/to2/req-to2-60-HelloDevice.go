package to2

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

func (h *To2Requestor) HelloDevice60(fdoTestID testcom.FDOTestID) (*fdoshared.TO2ProveOVHdrPayload, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	h.NonceTO2ProveOV60 = fdoshared.NewFdoNonce()

	helloDevice60 := fdoshared.HelloDevice60{
		MaxDeviceMessageSize: MaxDeviceMessageSize,
		Guid:                 h.Credential.DCGuid,
		NonceTO2ProveOV:      h.NonceTO2ProveOV60,
		KexSuiteName:         h.KexSuiteName,
		CipherSuiteName:      h.CipherSuiteName,
		EASigInfo:            h.Credential.DCSigInfo,
	}

	helloDevice60Byte, err := fdoshared.CborCust.Marshal(helloDevice60)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Error marshaling HelloDevice60. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DOT_60_POSITIVE {
		helloDevice60Byte = fdoshared.Conf_RandomCborBufferFuzzing(helloDevice60Byte)
	}

	resultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.SrvEntry, fdoshared.TO2_60_HELLO_DEVICE, helloDevice60Byte, &h.SrvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("HelloDevice60: " + err.Error())
	}

	if httpStatusCode != http.StatusOK {
		fdoErrInst, err := fdoshared.DecodeErrorResponse(resultBytes)
		if err == nil {
			return nil, nil, fmt.Errorf("HelloDevice60: %s", fdoErrInst.EMErrorStr)
		}
	}

	h.AuthzHeader = authzHeader

	var proveOVHdr61 fdoshared.CoseSignature
	err = fdoshared.CborCust.Unmarshal(resultBytes, &proveOVHdr61)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Failed to unmarshal HelloRVAck31. " + err.Error())
	}

	// Signature verification
	probableOwnerPubKey := proveOVHdr61.Unprotected.CUPHOwnerPubKey
	err = fdoshared.VerifyCoseSignature(proveOVHdr61, *probableOwnerPubKey)
	if err != nil {
		return nil, nil, err
	}

	h.ProveOVHdr61PubKey = *probableOwnerPubKey

	var proveOvdrPayload fdoshared.TO2ProveOVHdrPayload
	fdoError, err := fdoshared.TryCborUnmarshal(proveOVHdr61.Payload, &proveOvdrPayload)
	if err != nil {
		return nil, nil, err
	}

	if fdoError != nil {
		return nil, nil, errors.New("HelloDevice60: Received FDO Error: " + fdoError.Error())
	}

	err = proveOvdrPayload.EBSigInfo.Equal(helloDevice60.EASigInfo)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Failed SigInfo check. " + err.Error())
	}

	if !bytes.Equal(proveOvdrPayload.NonceTO2ProveOV[:], h.NonceTO2ProveOV60[:]) {
		return nil, nil, errors.New("HelloDevice60: DO returned wrong NonceTO2ProveOV")
	}

	err = fdoshared.VerifyHMac(proveOvdrPayload.OVHeader, proveOvdrPayload.HMac, h.Credential.DCHmacSecret)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Unknown Header HMac. " + err.Error())
	}

	if proveOvdrPayload.HelloDeviceHash.Type != h.Credential.DCHashAlg {
		return nil, nil, errors.New("HelloDevice60: Failed to verify HelloDeviceHash. Types don't match")
	}

	err = fdoshared.VerifyHash(helloDevice60Byte, proveOvdrPayload.HelloDeviceHash)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Failed to verify hello device Hash")
	}

	h.NonceTO2ProveDv61 = *proveOVHdr61.Unprotected.CUPHNonce
	h.XAKex = proveOvdrPayload.XAKeyExchange
	h.OvHmac = proveOvdrPayload.HMac

	h.Completed60 = true
	return &proveOvdrPayload, &testState, nil
}
