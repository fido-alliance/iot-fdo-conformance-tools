package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"

	"github.com/WebauthnWorks/fdo-rv/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

type RvTo1 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
}

func (h *RvTo1) Handle30HelloRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloRV30...")
	if !CheckHeaders(w, r, fdoshared.TO1_HELLO_RV_30) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)

	var helloRV30 fdoshared.HelloRV30
	err = cbor.Unmarshal(bodyBytes, &helloRV30)

	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_HELLO_RV_30, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// TODO - check to see if GUID exists. (RESOURCE_NOT_FOUND if not)
	_, err = h.ownersignDB.Get(helloRV30.Guid)
	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, fdoshared.TO1_HELLO_RV_30, "Could not find guid!", http.StatusBadRequest)
		return
	}

	nonceTO1Proof := make([]byte, 16)
	rand.Read(nonceTO1Proof)

	newSessionInst := SessionEntry{
		Protocol:      fdoshared.To1,
		NonceTO1Proof: nonceTO1Proof,
		Guid:          helloRV30.Guid,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO1_HELLO_RV_30, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloRVAck31 := fdoshared.HelloRVAck31{
		NonceTO1Proof: nonceTO1Proof,
		EBSigInfo:     helloRV30.EASigInfo,
	}

	helloRVAckBytes, _ := cbor.Marshal(helloRVAck31)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_HELLO_RV_ACK_31.ToString())
	w.WriteHeader(http.StatusOK)

	w.Write(helloRVAckBytes)
}

func (h *RvTo1) Handle32ProveToRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving ProveToRV32...")
	if !CheckHeaders(w, r, fdoshared.TO1_PROVE_TO_RV_32) {
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

	bodyBytes, err := ioutil.ReadAll(r.Body)

	var proveToRV32 fdoshared.ProveToRV32
	err = cbor.Unmarshal(bodyBytes, &proveToRV32)

	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to decode body /32 (1)!", http.StatusBadRequest)
		return
	}

	var pb fdoshared.EATPayloadBase
	err = cbor.Unmarshal(proveToRV32.Payload, &pb)
	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to decode body /32 (2)!", http.StatusBadRequest)
		return
	}

	if bytes.Compare(pb.EatNonce[:], session.NonceTO1Proof[:]) != 0 {
		log.Println("Nonce Invalid")
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "NonceTo1Proof mismatch", http.StatusBadRequest)
		return
	}

	// Get ownerSign from to0 storage
	ownerSign22, err := h.ownersignDB.Get(session.Guid)
	if err != nil {
		log.Println("Couldn't find item in database with guid" + err.Error())

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Server Error", http.StatusInternalServerError)
		return
	}
	var ownershipVoucher fdoshared.OwnershipVoucher
	cbor.Unmarshal(ownerSign22.To0d, &ownershipVoucher)

	var placeHolder_publicKey fdoshared.FdoPublicKey
	signatureIsValid, err := fdoshared.VerifyCoseSignature(proveToRV32, placeHolder_publicKey)
	if err != nil {
		log.Println("ProveToRV32: Error verigetInfo_response[GetInfoRespKeys.fying. " + err.Error())
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to verify signature ProveToRV32, some error", http.StatusBadRequest)
		return
	}

	if !signatureIsValid {
		log.Println("ProveToRV32: Signature is not valid!")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to verify signature!", http.StatusBadRequest)
		return
	}

	rvRedirect := fdoshared.RVRedirect33{
		RVRedirect: ownerSign22.To1d,
	}

	rvRedirectBytes, _ := cbor.Marshal(rvRedirect)

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_RV_REDIRECT_33.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(rvRedirectBytes)
}
