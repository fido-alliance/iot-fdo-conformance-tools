package to2

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

func (h *To2Requestor) Done70(fdoTestID testcom.FDOTestID) (*fdoshared.Done271, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	done70 := fdoshared.Done70{
		NonceTO2ProveDv: h.NonceTO2ProveDv61,
	}

	if fdoTestID == testcom.FIDO_DOT_70_BAD_NONCE_PROVE_DV_61 {
		done70.NonceTO2ProveDv = fdoshared.NewFdoNonce()
	}

	done70Bytes, _ := fdoshared.CborCust.Marshal(done70)

	if fdoTestID == testcom.FIDO_DOT_70_BAD_ENCODING {
		done70Bytes = fdoshared.Conf_RandomCborBufferFuzzing(done70Bytes)
	}

	done70BytesEnc, err := fdoshared.AddEncryptionWrapping(done70Bytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("Done70: Error encrypting... " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DOT_70_BAD_ENCRYPTION {
		done70BytesEnc, err = fdoshared.Conf_Fuzz_AddWrapping(done70BytesEnc, h.SessionKey, h.CipherSuiteName)
		if err != nil {
			return nil, nil, errors.New("DeviceServiceInfoReady66: Error encrypting... " + err.Error())
		}
	}

	rawResultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.SrvEntry, fdoshared.TO2_70_DONE, done70BytesEnc, &h.AuthzHeader)
	if fdoTestID != testcom.NULL_TEST {
		testState = h.confCheckResponse(rawResultBytes, fdoTestID, httpStatusCode)
		return nil, &testState, nil
	}

	if err != nil {
		return nil, nil, err
	}

	if httpStatusCode != http.StatusOK {
		fdoErrInst, err := fdoshared.DecodeErrorResponse(rawResultBytes)
		if err == nil {
			return nil, nil, fmt.Errorf("Done70: %s", fdoErrInst.EMErrorStr)
		}
	}

	if authzHeader != "" {
		h.AuthzHeader = authzHeader
	}

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("Done70: Error decrypting... " + err.Error())
	}

	var done271 fdoshared.Done271
	fdoError, err := fdoshared.TryCborUnmarshal(bodyBytes, &done271)
	if err != nil {
		return nil, nil, errors.New("Done70: Error decoding Done271... " + err.Error())
	}

	if fdoError != nil {
		return nil, nil, errors.New("Done70: Received FDO Error: " + fdoError.Error())
	}

	if !bytes.Equal(done271.NonceTO2SetupDv[:], h.NonceTO2SetupDv64[:]) {
		return nil, nil, errors.New("Done70: Error verifying Done271. Nonces do not match.")
	}

	return &done271, &testState, nil
}
