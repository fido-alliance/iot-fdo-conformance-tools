package fdodeviceimplementation

import (
	"errors"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

type To1Requestor struct {
	rvEntry     SRVEntry
	credential  fdoshared.WawDeviceCredential
	authzHeader string
}

func NewTo1Requestor(srvEntry SRVEntry, credential fdoshared.WawDeviceCredential) To1Requestor {
	return To1Requestor{
		rvEntry:    srvEntry,
		credential: credential,
	}
}

func (h *To1Requestor) confCheckResponse(bodyBytes []byte, fdoTestID testcom.FDOTestID, httpStatusCode int) testcom.FDOTestState {
	switch fdoTestID {

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_30, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	case testcom.ExpectGroupTests(testcom.FIDO_TEST_LIST_DEVT_32, fdoTestID):
		return testcom.ExpectFdoError(bodyBytes, fdoshared.MESSAGE_BODY_ERROR, httpStatusCode)

	}
	return testcom.FDOTestState{
		Passed: false,
		Error:  "Unsupported test " + string(fdoTestID),
	}
}

func (h *To1Requestor) HelloRV30(fdoTestID testcom.FDOTestID) (*fdoshared.HelloRVAck31, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState
	var helloRVAck31 fdoshared.HelloRVAck31

	helloRv30 := fdoshared.HelloRV30{
		Guid:      h.credential.DCGuid,
		EASigInfo: h.credential.DCSigInfo,
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_UNKNOWN_GUID {
		helloRv30.Guid = fdoshared.NewFdoGuid()
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_SIGINFO {
		helloRv30.EASigInfo = fdoshared.Conf_RandomTestFuzzSigInfo(helloRv30.EASigInfo)
	}

	helloRV30Bytes, err := cbor.Marshal(helloRv30)
	if err != nil {
		return nil, nil, errors.New("HelloRV30: Error marshaling HelloRV30. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_30_BAD_ENCODING {
		helloRV30Bytes = fdoshared.Conf_RandomCborBufferFuzzing(helloRV30Bytes)
	}

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(h.rvEntry, fdoshared.TO1_30_HELLO_RV, helloRV30Bytes, &h.rvEntry.AccessToken)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return &helloRVAck31, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("HelloRV30: Error sending RV request: " + err.Error())
	}

	h.authzHeader = authzHeader

	err = cbor.Unmarshal(resultBytes, &helloRVAck31)
	if err != nil {
		return nil, nil, errors.New("HelloRV30: Failed to unmarshal HelloRvAck31. " + err.Error())
	}

	return &helloRVAck31, &testState, nil
}

func (h *To1Requestor) ProveToRV32(helloRVAck31 fdoshared.HelloRVAck31, fdoTestID testcom.FDOTestID) (*fdoshared.CoseSignature, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	var proveToRV32Payload fdoshared.EATPayloadBase = fdoshared.EATPayloadBase{
		EatNonce: helloRVAck31.NonceTO1Proof,
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_TO1PROOF_NONCE {
		proveToRV32Payload.EatNonce = fdoshared.NewFdoNonce()
	}

	proveToRV32PayloadBytes, err := cbor.Marshal(proveToRV32Payload)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error generating ProveToRV32. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_ENCODING {
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

	proveToRV32Bytes, err := cbor.Marshal(proveToRV32)
	if err != nil {
		return nil, nil, errors.New("ProveToRV32: Error marshaling proveToRV32. " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DEVT_32_BAD_ENCODING {
		proveToRV32Bytes = fdoshared.Conf_RandomCborBufferFuzzing(proveToRV32Bytes)
	}

	var rvRedirect33 fdoshared.CoseSignature

	resultBytes, authzHeader, httpStatusCode, err := SendCborPost(h.rvEntry, fdoshared.TO1_32_PROVE_TO_RV, proveToRV32Bytes, &h.authzHeader)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(resultBytes, fdoTestID, httpStatusCode)
		return &rvRedirect33, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("HelloRV30: Error sending RV request: " + err.Error())
	}

	h.authzHeader = authzHeader
	err = cbor.Unmarshal(resultBytes, &rvRedirect33)

	if err != nil {
		return nil, &testState, errors.New("RVRedirect33: Failed to unmarshal RVRedirect33. " + err.Error())
	}

	return &rvRedirect33, &testState, nil
}
