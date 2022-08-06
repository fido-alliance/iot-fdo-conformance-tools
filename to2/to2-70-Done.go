package to2

import (
	"bytes"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) Done70(w http.ResponseWriter, r *http.Request) {
	log.Println("Done70: Receiving...")

	session, _, authorizationHeader, bodyBytes, err := h.receiveAndDecrypt(w, r, fdoshared.TO2_70_DONE)
	if err != nil {
		return
	}

	if session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		log.Println("Done70: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var done70 fdoshared.Done70
	err = cbor.Unmarshal(bodyBytes, &done70)
	if err != nil {
		log.Println("Done70: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if !bytes.Equal(done70.NonceTO2ProveDv[:], session.NonceTO2ProveDv61[:]) {
		log.Println("Done70: Can not verify NonceTO2ProveDv vs NonceTO2ProveDv61...")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Failed to verify Done70!", http.StatusBadRequest)
		return
	}

	var done271Payload = fdoshared.Done271{
		NonceTO2SetupDv: session.NonceTO2SetupDv64,
	}
	done271PayloadBytes, _ := cbor.Marshal(done271Payload)

	done271Bytes, err := fdoshared.AddEncryptionWrapping(done271PayloadBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Println("Done70: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_70_DONE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_71_DONE2.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(done271Bytes)
}
