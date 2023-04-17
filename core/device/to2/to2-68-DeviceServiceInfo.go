package to2

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/fido-alliance/fdo-device-implementation/common"
	fdoshared "github.com/fido-alliance/fdo-shared"
	"github.com/fido-alliance/fdo-shared/testcom"
	"github.com/fxamacker/cbor/v2"
)

func (h *To2Requestor) DeviceServiceInfo68(deviceServiceInfo68 fdoshared.DeviceServiceInfo68, fdoTestID testcom.FDOTestID) (*fdoshared.OwnerServiceInfo69, *testcom.FDOTestState, error) {
	var testState testcom.FDOTestState

	deviceServiceInfo68Bytes, _ := cbor.Marshal(deviceServiceInfo68)

	if fdoTestID == testcom.FIDO_DOT_68_BAD_ENCODING {
		deviceServiceInfo68Bytes = fdoshared.Conf_RandomCborBufferFuzzing(deviceServiceInfo68Bytes)
	}

	deviceServiceInfo68BytesEnc, err := fdoshared.AddEncryptionWrapping(deviceServiceInfo68Bytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfo68: Error encrypting... " + err.Error())
	}

	if fdoTestID == testcom.FIDO_DOT_68_BAD_ENCRYPTION {
		deviceServiceInfo68BytesEnc, err = fdoshared.Conf_Fuzz_AddWrapping(deviceServiceInfo68BytesEnc, h.SessionKey, h.CipherSuiteName)
		if err != nil {
			return nil, nil, errors.New("DeviceServiceInfoReady66: Error encrypting... " + err.Error())
		}
	}

	rawResultBytes, authzHeader, httpStatusCode, err := common.SendCborPost(h.SrvEntry, fdoshared.TO2_68_DEVICE_SERVICE_INFO, deviceServiceInfo68BytesEnc, &h.AuthzHeader)
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
		return nil, nil, errors.New("DeviceServiceInfo68: Error decrypting... " + err.Error())
	}

	var ownerServiceInfo69 fdoshared.OwnerServiceInfo69
	err = cbor.Unmarshal(bodyBytes, &ownerServiceInfo69)
	if err != nil {
		return nil, nil, errors.New("DeviceServiceInfo68: Error decoding OwnerServiceInfo69... " + err.Error())
	}

	return &ownerServiceInfo69, &testState, nil
}
