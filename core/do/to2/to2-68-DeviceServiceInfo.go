package to2

import (
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/fido-alliance/fdo-shared"
	listenertestsdeps "github.com/fido-alliance/fdo-shared/testcom/listener"
	"github.com/fxamacker/cbor/v2"
)

const MTU_BYTES = 1500

func (h *DoTo2) DeviceServiceInfo68(w http.ResponseWriter, r *http.Request) {
	log.Println("DeviceServiceInfo68: Receiving...")
	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY
	// var fdoTestId testcom.FDOTestID = testcom.NULL_TEST

	session, sessionId, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndDecrypt(w, r, fdoshared.TO2_68_DEVICE_SERVICE_INFO)
	if err != nil {
		return
	}

	if session.PrevCMD != fdoshared.TO2_67_OWNER_SERVICE_INFO_READY && session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected previous CMD to be %d or %d. Got %d", fdoshared.TO2_67_OWNER_SERVICE_INFO_READY, fdoshared.TO2_69_OWNER_SERVICE_INFO, session.PrevCMD), http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	// ----- MAIN BODY ----- //

	var deviceServiceInfo fdoshared.DeviceServiceInfo68
	err = cbor.Unmarshal(bodyBytes, &deviceServiceInfo)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Done70: Error encrypting..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	ownerServiceInfo := fdoshared.OwnerServiceInfo69{}

	if deviceServiceInfo.IsMoreServiceInfo {
		ownerServiceInfo.IsDone = false
		ownerServiceInfo.IsMoreServiceInfo = false

		session.DeviceSIMs = append(session.DeviceSIMs, *deviceServiceInfo.ServiceInfo)
	} else {
		if int(session.OwnerSIMsSendCounter+1) >= len(session.OwnerSIMs) {
			ownerServiceInfo.IsDone = true
			ownerServiceInfo.IsMoreServiceInfo = false

			// Updating session
			session.OwnerSIMsFinishedSending = true
		} else {
			ownerServiceInfo.IsDone = false
			ownerServiceInfo.IsMoreServiceInfo = true
		}
		ownerServiceInfo.ServiceInfo = &session.OwnerSIMs[session.OwnerSIMsSendCounter]

		session.OwnerSIMsSendCounter = session.OwnerSIMsSendCounter + 1
	}

	ownerServiceInfoBytes, _ := cbor.Marshal(ownerServiceInfo)

	// ----- MAIN BODY ENDS ----- //

	ownerServiceInfoEncBytes, err := fdoshared.AddEncryptionWrapping(ownerServiceInfoBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Println("DeviceServiceInfo68: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_68_DEVICE_SERVICE_INFO, "Internal server error!", http.StatusInternalServerError)
		return
	}

	session.PrevCMD = fdoshared.TO2_69_OWNER_SERVICE_INFO
	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		log.Println("ProveDevice64: Error saving session..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_68_DEVICE_SERVICE_INFO, "Internal server error!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_69_OWNER_SERVICE_INFO.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ownerServiceInfoEncBytes)
}
