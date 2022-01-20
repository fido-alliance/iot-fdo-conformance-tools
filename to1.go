package main

import (
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"

	"github.com/WebauthnWorks/fdo-rv/fdoshared"
)

type RvTo1 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
}

func (h *RvTo1) Handle30HelloRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloRV...")
	if !CheckHeaders(w, r, fdoshared.TO1_HELLO_RV_30) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_HELLO_RV_30, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// TODO

	nonceTO1Proof := make([]byte, 16)
	rand.Read(nonceTO1Proof)

	newSessionInst := SessionEntry{
		Protocol:      fdoshared.To1,
		NonceTO1Proof: nonceTO1Proof,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO1_HELLO_RV_30, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// TODO

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_HELLO_RV_ACK_31.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}

func (h *RvTo1) Handle32ProveToRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving OwnerSign22...")
	if !CheckHeaders(w, r, fdoshared.TO0_OWNER_SIGN_22) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := ExtractAuthorizationHeader(w, r, fdoshared.TO0_OWNER_SIGN_22)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if session.Protocol != fdoshared.To1 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_RV_REDIRECT_33.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
