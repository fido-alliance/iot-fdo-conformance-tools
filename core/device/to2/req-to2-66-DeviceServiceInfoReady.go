package to2

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/common"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

func (h *To2Requestor) DeviceServiceInfoReady66(fdoTestID testcom.FDOTestID) (*fdoshared.OwnerServiceInfoReady67, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	deviceSrvInfoReady := fdoshared.DeviceServiceInfoReady66{
		ReplacementHMac:       &h.OvHmac,
		MaxOwnerServiceInfoSz: &MaxOwnerServiceInfoSize,
	}
	deviceSrvInfoReadyBytes, _ := fdoshared.CborCust.Marshal(deviceSrvInfoReady)

	if fdoTestID == testcom.FIDO_DOT_66_BAD_SRVINFO_PAYLOAD {
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

	rawResultBytes, authzHeader, httpStatusCode, err := common.SendCborPost(h.SrvEntry, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, deviceSrvInfoReadyBytesEnc, &h.AuthzHeader)
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
			return nil, nil, fmt.Errorf("HelloDevice60: %s", fdoErrInst.EMErrorStr)
		}
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Error decrypting... " + err.Error())
	}

	var ownerServiceInfoReady67 fdoshared.OwnerServiceInfoReady67
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &ownerServiceInfoReady67)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfoReady66: Error decoding OwnerServiceInfoReady67... " + err.Error())
	}

	return &ownerServiceInfoReady67, &testState, nil
}
