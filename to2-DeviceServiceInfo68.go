package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

var devmod = map[string]string{
	"devmod:active":     "boolean",
	"devmod:os":         "string",
	"devmod:arch":       "string",
	"devmod:version":    "string",
	"devmod:device":     "string",
	"devmod:sep":        "string",
	"devmod:bin":        "string",
	"devmod:nummodules": "number",
	"devmod:modules":    "object",
}

var serviceInfo = map[string][]string{
	"REQUIRED": {"devmod:active", "devmod:os", "devmod:arch", "devmod:version", "devmod:device", "devmod:sep", "devmod:bin", "devmod:nummodules", "devmod:modules"},
	"OPTIONAL": {"devmod:sn", "devmod:pathsep", "devmod:nl", "devmod:tmp", "devmod:dir", "devmod:progenv", "devmod:mudurl"},
}

const MTU_BYTES = 1500

// Sends as many Owner to Device ServiceInfo entries as will conveniently fit into a message, based on protocol and implementation constraints.
// No idea what this is referring to
func (h *DoTo2) DeviceServiceInfo68(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving DeviceServiceInfo68...")

	if !CheckHeaders(w, r, fdoshared.TO2_DEVICE_SERVICE_INFO_68) {

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to read body!", http.StatusBadRequest)
		return
	}

	headerIsOk, sessionId, _ := ExtractAuthorizationHeader(w, r, fdoshared.TO2_DEVICE_SERVICE_INFO_68)
	if !headerIsOk {

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to decode body", http.StatusBadRequest)
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}
	if session.NextCmd != fdoshared.TO2_DEVICE_SERVICE_INFO_68 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Unauthorized. Didn't call /66 (1)", http.StatusUnauthorized)
		return
	}

	bodyBytes2, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// DELETE
	hex.EncodeToString(bodyBytes2)
	bodyBytesAsString := string(bodyBytes2)
	bodyBytes, err := hex.DecodeString(bodyBytesAsString)
	// DELETE

	if len(bodyBytes) > int(session.MaxDeviceServiceInfoSz) || len(bodyBytes) > MTU_BYTES {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, fmt.Sprintf("Message was too long! Must be %s", session.MaxDeviceServiceInfoSz), http.StatusBadRequest)
		return
	}

	sessionKey := session.SessionKey
	log.Println(sessionKey) // used to decrypt
	// Insert decryption logic here...
	decryptionBytes := bodyBytes
	// voucher := session.Voucher

	var DeviceServiceInfo68 fdoshared.DeviceServiceInfo68
	err = cbor.Unmarshal(decryptionBytes, &DeviceServiceInfo68)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to decode body!", http.StatusBadRequest)
		return
	}
	// bodyBytes will be encrypted
	// need to decrypt it using the sessionKey

	// If the previous TO2.OwnerServiceInfo.IsMoreServiceInfo had value True, then this message MUST contain:
	if session.OwnerServiceInfoIsMoreServiceInfoIsTrue {
		if DeviceServiceInfo68.IsMoreServiceInfo || DeviceServiceInfo68.ServiceInfo != nil {
			RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Invalid Payload", http.StatusBadRequest)
			return
		}
	}

	// On the first ServiceInfo message, the Device must include the devmod module messages.
	if session.ServiceInfoMsgNo == 0 {
		// Check for devmod module messages
		for _, kv := range *DeviceServiceInfo68.ServiceInfo {
			log.Println(kv.ServiceInfoKey)
			// check to see kv.ServiceInfoKey is in devmod
			log.Println(kv.ServiceInfoVal)
			// get actual type of value, based on key
			// get specified type of value
			// if specified type != actual type => error
		}

	}
	session.ServiceInfoMsgNo++
	h.session.UpdateSessionEntry(sessionId, *session)

	var OwnerServiceInfo = fdoshared.OwnerServiceInfo69{}
	// The IsMoreServiceInfo indicates whether the Device has more ServiceInfo to send.
	// If this flag is True, then the subsequent TO2.OwnerServiceInfo message MUST be empty, allowing the Device to send additional ServiceInfo items.
	if DeviceServiceInfo68.IsMoreServiceInfo {
		OwnerServiceInfo.IsMoreServiceInfo = false
		OwnerServiceInfo.IsDone = false
		OwnerServiceInfo.ServiceInfo = nil
	}
	OwnerServiceInfoReadyBytes, err := cbor.Marshal(OwnerServiceInfo)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to decode body!", http.StatusBadRequest)
		return
	}
	// Encode(OwnerServiceInfoReadyBytes)
	// => Encrypt OwnerServiceInfoReadyBytes inside an ETM object

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_OWNER_SERVICE_INFO_69.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(OwnerServiceInfoReadyBytes)
}
