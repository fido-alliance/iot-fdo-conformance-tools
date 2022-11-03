package to2

import (
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

const MTU_BYTES = 1500

func (h *DoTo2) DeviceServiceInfo68(w http.ResponseWriter, r *http.Request) {
	log.Println("DeviceServiceInfo68: Receiving...")

	session, sessionId, authorizationHeader, bodyBytes, err := h.receiveAndDecrypt(w, r, fdoshared.TO2_68_DEVICE_SERVICE_INFO)
	if err != nil {
		return
	}

	if session.PrevCMD != fdoshared.TO2_67_OWNER_SERVICE_INFO_READY && session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		log.Println("DeviceServiceInfo68: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_68_DEVICE_SERVICE_INFO, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// ----- MAIN BODY ----- //

	var deviceServiceInfo fdoshared.DeviceServiceInfo68
	err = cbor.Unmarshal(bodyBytes, &deviceServiceInfo)
	if err != nil {
		log.Println("DeviceServiceInfo68: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_68_DEVICE_SERVICE_INFO, "Failed to decode body!", http.StatusBadRequest)
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
