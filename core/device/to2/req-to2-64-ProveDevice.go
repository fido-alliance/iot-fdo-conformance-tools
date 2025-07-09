package to2

import (
	"errors"
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

// REQUESTOR
func (h *To2Requestor) ProveDevice64(fdoTestID testcom.FDOTestID) (*fdoshared.TO2SetupDevicePayload, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	// KEX
	kex, err := fdoshared.GenerateXABKeyExchange(h.KexSuiteName, &h.ProveOVHdr61PubKey)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error generating XBKeyExchange... " + err.Error())
	}
	h.XBKEXParams = *kex

	// Session
	newSessionKey, err := fdoshared.DeriveSessionKey(h.XBKEXParams, h.XAKex, true, nil)
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
		EatUEID:  fdoshared.GenerateEatGuid(h.Credential.DCGuid),
	}

	if fdoTestID == testcom.FIDO_DOT_64_BAD_NONCE_PROVEDV61 {
		eatPayload.EatNonce = fdoshared.NewFdoNonce()
	}

	eatPayloadBytes, _ := fdoshared.CborCust.Marshal(eatPayload)
	if fdoTestID == testcom.FIDO_DOT_64_BAD_EAT_PAYLOAD {
		eatPayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(eatPayloadBytes)
	}

	// Private key
	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.Credential.DCPrivateKeyDer)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error extract private key... " + err.Error())
	}

	// EAT and exchange
	proveDevice, err := fdoshared.GenerateCoseSignature(eatPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{EUPHNonce: &h.NonceTO2SetupDv64}, privateKeyInst, h.Credential.DCSigInfo.SgType)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error generating device EAT... " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DOT_64_BAD_SIGNATURE {
		proveDevice.Signature = fdoshared.Conf_RandomCborBufferFuzzing(proveDevice.Signature)
	}

	proveDeviceBytes, _ := fdoshared.CborCust.Marshal(proveDevice)

	if fdoTestID == testcom.FIDO_DOT_64_BAD_ENCODING {
		proveDeviceBytes = fdoshared.Conf_RandomCborBufferFuzzing(proveDeviceBytes)
	}

	rawResultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.SrvEntry, fdoshared.TO2_64_PROVE_DEVICE, proveDeviceBytes, &h.AuthzHeader)
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
			return nil, nil, fmt.Errorf("ProveDevice64: Server returned FDO error: %s %d", fdoErrInst.EMErrorStr, fdoErrInst.EMErrorCode)
		}
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decrypting... " + err.Error())
	}

	var setupDevice fdoshared.CoseSignature
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &setupDevice)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decoding SetupDevice65... " + err.Error())
	}

	var to2SetupDevicePayload fdoshared.TO2SetupDevicePayload
	fdoError, err := fdoshared.TryCborUnmarshal(setupDevice.Payload, &to2SetupDevicePayload)
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error decoding SetupDevice65 Payload... " + err.Error())
	}

	err = fdoshared.VerifyCoseSignature(setupDevice, to2SetupDevicePayload.ReplacementOwner2Key)
	if err != nil {
		return nil, nil, err
	}

	if fdoError != nil {
		return nil, nil, errors.New("ProveDevice64: Received FDO Error: " + fdoError.Error())
	}

	if !to2SetupDevicePayload.NonceTO2SetupDv.Equals(h.NonceTO2SetupDv64) {
		return nil, nil, errors.New("ProveDevice64: NonceTO2SetupDv64 nonces don't match...")
	}

	err = to2SetupDevicePayload.Validate()
	if err != nil {
		return nil, nil, errors.New("ProveDevice64: Error validating SetupDevice65 Payload... " + err.Error())
	}

	h.CredentialReuse = to2SetupDevicePayload.IsCredentialReuse(h.Credential.DCGuid)
	if h.CredentialReuse {
		h.ReplacementCredential = to2SetupDevicePayload
	}

	return &to2SetupDevicePayload, &testState, nil
}
