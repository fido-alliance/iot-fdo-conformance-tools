package to2

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/common"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	"github.com/fxamacker/cbor/v2"
)

// REQUESTOR
func (h *To2Requestor) ProveDevice64(fdoTestID testcom.FDOTestID) (*fdoshared.TO2SetupDevicePayload, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	// KEX
	kex, err := fdoshared.GenerateXAKeyExchange(h.KexSuiteName)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error generating XBKeyExchange... " + err.Error())
	}
	h.XBKEXParams = *kex

	// KEX
	newSessionKey, err := fdoshared.DeriveSessionKey(&h.XBKEXParams, h.XAKex, true)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error generating session ShSe... " + err.Error())
	}
	h.SessionKey = *newSessionKey

	// Nonce
	h.NonceTO2SetupDv64 = fdoshared.NewFdoNonce()

	// EAT FDO Payload
	to2ProveDevicePayload := fdoshared.TO2ProveDevicePayload{
		XBKeyExchange: h.XBKEXParams.XAKeyExchange,
	}

	// EAT Payload
	eatPayload := fdoshared.EATPayloadBase{
		EatNonce: h.NonceTO2ProveDv61,
		EatFDO:   to2ProveDevicePayload,
	}

	if fdoTestID == testcom.FIDO_DOT_64_BAD_NONCE_PROVEDV61 {
		eatPayload.EatNonce = fdoshared.NewFdoNonce()
	}

	eatPayloadBytes, _ := cbor.Marshal(eatPayload)
	if fdoTestID == testcom.FIDO_DOT_64_BAD_NONCE_PROVEDV61 {
		eatPayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(eatPayloadBytes)
	}

	// Private key
	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.Credential.DCPrivateKeyDer)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error extract private key... " + err.Error())
	}

	// EAT and exchange
	proveDevice, err := fdoshared.GenerateCoseSignature(eatPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{EUPHNonce: h.NonceTO2SetupDv64}, privateKeyInst, h.Credential.DCSigInfo.SgType)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error generating device EAT... " + err.Error())

	}

	if fdoTestID == testcom.FIDO_DOT_64_BAD_SIGNATURE {
		proveDevice.Signature = fdoshared.Conf_RandomCborBufferFuzzing(proveDevice.Signature)
	}

	proveDeviceBytes, _ := cbor.Marshal(proveDevice)

	rawResultBytes, authzHeader, httpStatusCode, err := common.SendCborPost(h.SrvEntry, fdoshared.TO2_64_PROVE_DEVICE, proveDeviceBytes, &h.AuthzHeader)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(rawResultBytes, fdoTestID, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, errors.New("ProveDevice64: " + err.Error())
	}

	if httpStatusCode != http.StatusOK {
		fdoErrInst, err := fdoshared.DecodeErrorResponse(rawResultBytes)
		if err == nil {
			return nil, nil, fmt.Errorf("HelloDevice60: %s", fdoErrInst.EMErrorStr)
		}
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decrypting... " + err.Error())
	}

	var setupDevice fdoshared.CoseSignature
	err = cbor.Unmarshal(bodyBytes, &setupDevice)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decoding SetupDevice65... " + err.Error())
	}

	err = fdoshared.VerifyCoseSignature(setupDevice, h.ProveOVHdr61PubKey)
	if err != nil {
		return nil, nil, err
	}

	var to2SetupDevicePayload fdoshared.TO2SetupDevicePayload
	err = cbor.Unmarshal(setupDevice.Payload, &to2SetupDevicePayload)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decoding SetupDevice65 Payload... " + err.Error())
	}

	if !bytes.Equal(to2SetupDevicePayload.NonceTO2SetupDv[:], h.NonceTO2SetupDv64[:]) {
		return nil, nil, errors.New("ProveDevice64: NonceTO2SetupDv64 nonces don't match...")
	}

	return &to2SetupDevicePayload, &testState, nil
}
