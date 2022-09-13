package fdodeviceimplementation

import (
	"bytes"
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *To2Requestor) HelloDevice60(fdoTestID testcom.FDOTestID) (*fdoshared.TO2ProveOVHdrPayload, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	h.NonceTO2ProveOV60 = fdoshared.NewFdoNonce()

	helloDevice60Byte, err := cbor.Marshal(fdoshared.HelloDevice60{
		MaxDeviceMessageSize: MaxDeviceMessageSize,
		Guid:                 h.Credential.DCGuid,
		NonceTO2ProveOV:      h.NonceTO2ProveOV60,
		KexSuiteName:         h.KexSuiteName,
		CipherSuiteName:      h.CipherSuiteName,
		EASigInfo:            h.Credential.DCSigInfo,
	})

	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Error marshaling HelloDevice60. " + err.Error())
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(h.SrvEntry, fdoshared.TO2_60_HELLO_DEVICE, helloDevice60Byte, &h.SrvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
	}

	if err != nil {
		return nil, nil, errors.New("HelloDevice60: " + err.Error())
	}

	h.AuthzHeader = authzHeader

	var proveOVHdr61 fdoshared.CoseSignature
	err = cbor.Unmarshal(resultBytes, &proveOVHdr61)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Failed to unmarshal HelloRVAck31. " + err.Error())
	}

	// Signature verification
	probableOwnerPubKey := proveOVHdr61.Unprotected.CUPHOwnerPubKey
	err = fdoshared.VerifyCoseSignature(proveOVHdr61, probableOwnerPubKey)
	if err != nil {
		return nil, nil, err
	}

	h.ProveOVHdr61PubKey = probableOwnerPubKey

	var proveOvdrPayload fdoshared.TO2ProveOVHdrPayload
	err = cbor.Unmarshal(proveOVHdr61.Payload, &proveOvdrPayload)
	if err != nil {
		return nil, nil, err
	}

	if !bytes.Equal(proveOvdrPayload.NonceTO2ProveOV[:], h.NonceTO2ProveOV60[:]) {
		return nil, nil, errors.New("HelloDevice60: DO returned wrong NonceTO2ProveOV!")
	}

	err = fdoshared.VerifyHMac(proveOvdrPayload.OVHeader, proveOvdrPayload.HMac, h.Credential.DCHmacSecret)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Unknown Header HMac!")
	}

	err = fdoshared.VerifyHash(helloDevice60Byte, proveOvdrPayload.HelloDeviceHash)
	if err != nil {
		return nil, nil, errors.New("HelloDevice60: Failed to verify hello device Hash!")
	}

	h.NonceTO2ProveDv61 = proveOVHdr61.Unprotected.CUPHNonce
	h.XAKex = proveOvdrPayload.XAKeyExchange
	h.OvHmac = proveOvdrPayload.HMac

	h.Completed60 = true
	return &proveOvdrPayload, &testState, nil
}
