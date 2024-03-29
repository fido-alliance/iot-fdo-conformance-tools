package to1

import (
	"errors"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

func (h *To1Requestor) ProveToRV32(helloRVAck31 fdoshared.HelloRVAck31, fdoTestID testcom.FDOTestID) (*fdoshared.CoseSignature, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	var proveToRV32Payload fdoshared.EATPayloadBase = fdoshared.EATPayloadBase{
		EatNonce: helloRVAck31.NonceTO1Proof,
		EatUEID:  fdoshared.GenerateEatGuid(h.credential.DCGuid),
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_TO1PROOF_NONCE {
		proveToRV32Payload.EatNonce = fdoshared.NewFdoNonce()
	}

	proveToRV32PayloadBytes, err := fdoshared.CborCust.Marshal(proveToRV32Payload)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error generating ProveToRV32 payload. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_PROVE_TO_RV_PAYLOAD_ENCODING {
		proveToRV32PayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(proveToRV32PayloadBytes)
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.credential.DCPrivateKeyDer)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error extracting private key from voucher. " + err.Error())
	}

	sgType := helloRVAck31.EBSigInfo.SgType

	proveToRV32, err := fdoshared.GenerateCoseSignature(proveToRV32PayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, sgType)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error generating ProveToRV32. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_SIGNATURE {
		proveToRV32.Signature = fdoshared.Conf_RandomCborBufferFuzzing(proveToRV32.Signature)
	}

	proveToRV32Bytes, err := fdoshared.CborCust.Marshal(proveToRV32)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error marshaling proveToRV32. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_ENCODING {
		proveToRV32Bytes = fdoshared.Conf_RandomCborBufferFuzzing(proveToRV32Bytes)
	}

	var rvRedirect33 fdoshared.CoseSignature

	resultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.rvEntry, fdoshared.TO1_32_PROVE_TO_RV, proveToRV32Bytes, &h.authzHeader)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return &rvRedirect33, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("RVRedirect33: Error sending RV request: " + err.Error())
	}

	h.authzHeader = authzHeader
	fdoError, err := fdoshared.TryCborUnmarshal(resultBytes, &rvRedirect33)
	if err != nil {
		return nil, &testState, errors.New("RVRedirect33: Failed to unmarshal RVRedirect33. " + err.Error())
	}

	if fdoError != nil {
		return nil, &testState, errors.New("RVRedirect33: Received FDO Error: " + fdoError.Error())
	}

	return &rvRedirect33, &testState, nil
}
