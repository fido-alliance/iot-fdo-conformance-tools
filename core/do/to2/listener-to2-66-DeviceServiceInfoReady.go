package to2

import (
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	listenertestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/listener"
)

const MAX_DEVICE_SERVICE_INFO_SIZE uint16 = 1300

func (h *DoTo2) DeviceServiceInfoReady66(w http.ResponseWriter, r *http.Request) {
	log.Println("DeviceServiceInfoReady66: Receiving...")

	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST

	session, sessionId, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndDecrypt(w, r, currentCmd)
	if err != nil {
		return
	}

	if testcomListener != nil && !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To2.CheckExpectedCmd(currentCmd) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO2 %d. Got %d", testcomListener.To2.ExpectedCmd, currentCmd))
		} else if testcomListener.To2.CurrentTestIndex != 0 {
			testcomListener.To2.PushSuccess()
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	if session.PrevCMD != fdoshared.TO2_65_SETUP_DEVICE {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected previous CMD to be %d. Got %d", fdoshared.TO2_65_SETUP_DEVICE, session.PrevCMD), http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	// ----- MAIN BODY ----- //

	var deviceServiceInfoReady fdoshared.DeviceServiceInfoReady66
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &deviceServiceInfoReady)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode DeviceServiceInfoReady66! "+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// maxOwnerServiceInfoSz negotiation
	maxDeviceServiceInfoSz := MAX_DEVICE_SERVICE_INFO_SIZE

	if deviceServiceInfoReady.MaxOwnerServiceInfoSz != nil {
		maxDeviceServiceInfoSz = *deviceServiceInfoReady.MaxOwnerServiceInfoSz
	}

	var ownerServiceInfoReadyPayload = fdoshared.OwnerServiceInfoReady67{
		MaxDeviceServiceInfoSz: &maxDeviceServiceInfoSz,
	}
	ownerServiceInfoReadyPayloadBytes, _ := fdoshared.CborCust.Marshal(ownerServiceInfoReadyPayload)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_66_BAD_ENCODING {
		ownerServiceInfoReadyPayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(ownerServiceInfoReadyPayloadBytes)
	}

	// ----- MAIN BODY ENDS ----- //
	ownerServiceInfoReadyBytes, err := fdoshared.AddEncryptionWrapping(ownerServiceInfoReadyPayloadBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Failed to encrypt OwnerServiceInfoReady. "+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_66_BAD_ENC_WRAPPING {
		ownerServiceInfoReadyBytes, err = fdoshared.Conf_Fuzz_AddWrapping(ownerServiceInfoReadyBytes, session.SessionKey, session.CipherSuiteName)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Failed to fuzz encrypt OwnerServiceInfoReady. "+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
			return
		}
	}

	// Stores MaxSz for 68
	session.OwnerSIMs, err = h.GetOwnerSIMs(session.Guid)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error generating SIMs. "+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	session.MaxDeviceServiceInfoSz = maxDeviceServiceInfoSz
	session.PrevCMD = fdoshared.TO2_67_OWNER_SERVICE_INFO_READY
	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error saving session..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To2.CheckExpectedCmd(currentCmd) {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteCmdAndSetNext(fdoshared.TO2_68_DEVICE_SERVICE_INFO)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_67_OWNER_SERVICE_INFO_READY.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ownerServiceInfoReadyBytes)
}
