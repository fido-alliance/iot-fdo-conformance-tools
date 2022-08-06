package main

import (
	"errors"

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

func (h *To1Requestor) HelloRV30() (fdoshared.HelloRVAck31, error) {
	var helloRVAck31 fdoshared.HelloRVAck31

	helloRV30Bytes, err := cbor.Marshal(fdoshared.HelloRV30{
		Guid:      h.credential.DCGuid,
		EASigInfo: h.credential.DCSigInfo,
	})

	if err != nil {
		return helloRVAck31, errors.New("HelloRV30: Error marshaling HelloRV30. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO1_30_HELLO_RV, helloRV30Bytes, &h.rvEntry.AccessToken)
	if err != nil {
		return helloRVAck31, errors.New("Hello30: " + err.Error())
	}

	h.authzHeader = authzHeader

	err = cbor.Unmarshal(resultBytes, &helloRVAck31)
	if err != nil {
		return helloRVAck31, errors.New("HelloRV30: Failed to unmarshal HelloRVAck31. " + err.Error())
	}

	return helloRVAck31, nil
}

func (h *To1Requestor) ProveToRV32(helloRVAck31 fdoshared.HelloRVAck31) (*fdoshared.CoseSignature, error) {

	var proveToRV32Payload fdoshared.EATPayloadBase = fdoshared.EATPayloadBase{
		EatNonce: helloRVAck31.NonceTO1Proof,
	}

	proveToRV32PayloadBytes, err := cbor.Marshal(proveToRV32Payload)
	if err != nil {
		return nil, errors.New("ProveToRV32: Error generating ProveToRV32. " + err.Error())
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.credential.DCPrivateKeyDer)
	if err != nil {
		return nil, errors.New("ProveToRV32: Error extracting private key from voucher. " + err.Error())
	}

	sgType := helloRVAck31.EBSigInfo.SgType

	proveToRV32, err := fdoshared.GenerateCoseSignature(proveToRV32PayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, sgType)
	if err != nil {
		return nil, errors.New("ProveToRV32: Error generating ProveToRV32. " + err.Error())
	}

	proveToRV32Bytes, err := cbor.Marshal(proveToRV32)
	if err != nil {
		return nil, errors.New("ProveToRV32: Error marshaling proveToRV32. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.rvEntry, fdoshared.TO1_32_PROVE_TO_RV, proveToRV32Bytes, &h.authzHeader)
	if err != nil {
		return nil, errors.New("Hello30: " + err.Error())
	}

	h.authzHeader = authzHeader

	var rvRedirect33 fdoshared.CoseSignature

	err = cbor.Unmarshal(resultBytes, &rvRedirect33)

	if err != nil {
		return nil, errors.New("RVRedirect33: Failed to unmarshal RVRedirect33. " + err.Error())
	}

	return &rvRedirect33, nil
}
