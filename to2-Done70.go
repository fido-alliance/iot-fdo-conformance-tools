package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) Done70(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving Done70...")

	if !CheckHeaders(w, r, fdoshared.TO2_DONE_70) {
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DONE_70, "Failed to read body!", http.StatusBadRequest)
		return
	}

	headerIsOk, sessionId, _ := ExtractAuthorizationHeader(w, r, fdoshared.TO2_DONE_70)
	if !headerIsOk {
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_DONE_70, "Failed to decode body", http.StatusBadRequest)
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}
	if session.NextCmd != fdoshared.TO2_DONE_70 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Unauthorized. Didn't call /68 (1)", http.StatusUnauthorized)
		return
	}

	bodyBytes2, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// DELETE
	hex.EncodeToString(bodyBytes2)
	bodyBytesAsString := string(bodyBytes2)
	bodyBytes, err := hex.DecodeString(bodyBytesAsString)
	// DELETE

	sessionKey := session.SessionKey
	log.Println(sessionKey) // used to decrypt
	// Insert decryption logic here...
	decryptionBytes := bodyBytes
	// voucher := session.Voucher

	var Done70 fdoshared.Done70
	err = cbor.Unmarshal(decryptionBytes, &Done70)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Failed to decode body!", http.StatusBadRequest)
		return
	}
	// bodyBytes will be encrypted
	// need to decrypt it using the sessionKey
	if bytes.Compare(Done70.NonceTO2ProveDv, session.NonceTO2ProveDv61) != 0 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Nonce Error!", http.StatusBadRequest)
		return
	}

	var Done2 = fdoshared.Done271{
		NonceTO2SetupDv: session.NonceTO2SetupDv,
	}

	Done2Bytes, err := cbor.Marshal(Done2)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_DONE_70, "Failed to decode body!", http.StatusBadRequest)
		return
	}
	// Encode(OwnerServiceInfoReadyBytes)
	// => Encrypt OwnerServiceInfoReadyBytes inside an ETM object

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_OWNER_SERVICE_INFO_69.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(Done2Bytes)
}
