package to2

import (
	"errors"
	"fmt"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

func (h *To2Requestor) DeviceServiceInfoReady66(fdoTestID testcom.FDOTestID) (*fdoshared.OwnerServiceInfoReady67, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	deviceSrvInfoReady := fdoshared.DeviceServiceInfoReady66{
		ReplacementHMac:       &h.OvHmac,
		MaxOwnerServiceInfoSz: &MaxOwnerServiceInfoSize,
	}

	if h.CredentialReuse {
		deviceSrvInfoReady.ReplacementHMac = nil
	}

	deviceSrvInfoReadyBytes, _ := fdoshared.CborCust.Marshal(deviceSrvInfoReady)

	if fdoTestID == testcom.FIDO_DOT_66_BAD_ENCODING {
		deviceSrvInfoReadyBytes = fdoshared.Conf_RandomCborBufferFuzzing(deviceSrvInfoReadyBytes)
	}

	deviceSrvInfoReadyBytesEnc, err := fdoshared.AddEncryptionWrapping(deviceSrvInfoReadyBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Error encrypting... " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DOT_66_BAD_ENCRYPTION {
		deviceSrvInfoReadyBytesEnc, err = fdoshared.Conf_Fuzz_AddWrapping(deviceSrvInfoReadyBytesEnc, h.SessionKey, h.CipherSuiteName)
		if err != nil {
			return nil, nil, errors.New("DeviceServiceInfoReady66: Error encrypting... " + err.Error())
		}
	}

	rawResultBytes, authzHeader, httpStatusCode, err := fdoshared.SendCborPost(h.SrvEntry, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, deviceSrvInfoReadyBytesEnc, &h.AuthzHeader)
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
			return nil, nil, fmt.Errorf("DeviceServiceInfoReady66: %s", fdoErrInst.EMErrorStr)
		}
	}

	if authzHeader != "" {
		h.AuthzHeader = authzHeader
	}

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Error decrypting... " + err.Error())
	}

	var ownerServiceInfoReady67 fdoshared.OwnerServiceInfoReady67
	fdoError, err := fdoshared.TryCborUnmarshal(bodyBytes, &ownerServiceInfoReady67)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Error decoding OwnerServiceInfoReady67... " + err.Error())
	}

	if fdoError != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Received FDO Error: " + fdoError.Error())
	}

	return &ownerServiceInfoReady67, &testState, nil
}
