package to2

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
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

// ORIGINAL:
// 8443a10105a13a010f01bd830000f658458347a1013a010f01bfa23a010f01bd830000f60550eca62b5723f86c00c26084abffe35676581ed3fade08fb3761c19622f2be21d582551a85c9ca694b5d1b5e33e155e23a5820befd7fd86927830a118804f93accc3dfca2e3952d0e7d0bb25789c7d91037ef4
// Without decryption
//

// Sends as many Owner to Device ServiceInfo entries as will conveniently fit into a message, based on protocol and implementation constraints.
// No idea what this is referring to
func (h *DoTo2) DeviceServiceInfo68(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving DeviceServiceInfo68...")

	if !CheckHeaders(w, r, fdoshared.TO2_DEVICE_SERVICE_INFO_68) {

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Unauthorized. Header token invalid", http.StatusBadRequest)
		return
	}

	headerIsOk, sessionId, _ := ExtractAuthorizationHeader(w, r, fdoshared.TO2_DEVICE_SERVICE_INFO_68)
	if !headerIsOk {

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Unauthorized. Header token invalid", http.StatusBadRequest)
		return
	}

	session, err := h.Session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Unauthorized.", http.StatusUnauthorized)
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
		log.Println(decryptionBytes)
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Failed to decode body 2!", http.StatusBadRequest)
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

	// TODO:
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
	h.Session.UpdateSessionEntry(sessionId, *session)

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
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DEVICE_SERVICE_INFO_68, "Internal Server Error!", http.StatusInternalServerError)
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
