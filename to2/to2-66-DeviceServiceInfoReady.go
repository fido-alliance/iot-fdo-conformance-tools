package to2

import (
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

const MAX_DEVICE_SERVICE_INFO_SIZE uint16 = 1300

func (h *DoTo2) DeviceServiceInfoReady66(w http.ResponseWriter, r *http.Request) {
	log.Println("DeviceServiceInfoReady66: Receiving...")

	session, sessionId, authorizationHeader, bodyBytes, err := h.receiveAndDecrypt(w, r, fdoshared.TO2_64_PROVE_DEVICE)
	if err != nil {
		return
	}

	if session.PrevCMD != fdoshared.TO2_65_SETUP_DEVICE {
		log.Println("DeviceServiceInfoReady66: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// ----- MAIN BODY ----- //

	var deviceServiceInfoReady fdoshared.DeviceServiceInfoReady66
	err = cbor.Unmarshal(bodyBytes, &deviceServiceInfoReady)
	if err != nil {
		log.Println("DeviceServiceInfoReady66: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Failed to decode body!", http.StatusBadRequest)
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
	ownerServiceInfoReadyPayloadBytes, _ := cbor.Marshal(ownerServiceInfoReadyPayload)

	// ----- MAIN BODY ENDS ----- //

	ownerServiceInfoReadyBytes, err := fdoshared.AddEncryptionWrapping(ownerServiceInfoReadyPayloadBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Println("DeviceServiceInfoReady66: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Internal server error!", http.StatusInternalServerError)
		return
	}

	// Stores MaxSz for 68
	session.MaxDeviceServiceInfoSz = maxDeviceServiceInfoSz
	session.PrevCMD = fdoshared.TO2_67_OWNER_SERVICE_INFO_READY
	err = h.Session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		log.Println("DeviceServiceInfoReady66: Error saving session..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Internal server error!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_67_OWNER_SERVICE_INFO_READY.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ownerServiceInfoReadyBytes)
}
