package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

const ServerWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type RvTo0 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
}

func (h *RvTo0) Handle20Hello(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving Hello20...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO0_20_HELLO) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var helloMsg fdoshared.Hello20

	err = cbor.Unmarshal(bodyBytes, &helloMsg)
	if err != nil {
		log.Println("Error decoding Hello20. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	nonceTO0Sign := fdoshared.NewFdoNonce()

	newSessionInst := SessionEntry{
		Protocol:     fdoshared.To0,
		NonceTO0Sign: nonceTO0Sign,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_20_HELLO, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck := fdoshared.HelloAck21{
		NonceTO0Sign: nonceTO0Sign,
	}

	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_21_HELLO_ACK.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}

func (h *RvTo0) Handle22OwnerSign(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving OwnerSign22...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO0_22_OWNER_SIGN) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO0_22_OWNER_SIGN)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if session.Protocol != fdoshared.To0 {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Unauthorized", http.StatusUnauthorized)
		return
	}

	/* ----- Process Body ----- */
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var ownerSign fdoshared.OwnerSign22
	err = cbor.Unmarshal(bodyBytes, &ownerSign)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	var to0d fdoshared.To0d
	err = cbor.Unmarshal(ownerSign.To0d, &to0d)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	var to1dPayload fdoshared.To1dBlobPayload
	err = cbor.Unmarshal(ownerSign.To1d.Payload, &to1dPayload)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	/* ----- Verify OwnerSign ----- */

	if !bytes.Equal(to0d.NonceTO0Sign[:], session.NonceTO0Sign[:]) {
		log.Println("OwnerSign22: NonceTO0Sign does not match!")
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	err = to0d.OwnershipVoucher.Validate()
	if err != nil {
		log.Println("OwnerSign22: Error verifying voucher. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate voucher!", http.StatusBadRequest)
		return
	}

	ovHeader, err := to0d.OwnershipVoucher.GetOVHeader()
	if err != nil {
		log.Println("OwnerSign22: Error decoding header. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	// Verify To1D
	finalPublicKey, err := to0d.OwnershipVoucher.GetFinalOwnerPublicKey()
	if err != nil {
		log.Println("OwnerSign22: Error decoding final owner public key. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	err = fdoshared.VerifyCoseSignature(ownerSign.To1d, finalPublicKey)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to1d. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign 4!", http.StatusBadRequest)
		return
	}

	// Verify To0D Hash
	err = fdoshared.VerifyHash(ownerSign.To0d, to1dPayload.To1dTo0dHash)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to0dHash. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign 6!", http.StatusBadRequest)
		return
	}

	// Agreeing on timeout and saving
	agreedWaitSeconds := ServerWaitSeconds
	if to0d.WaitSeconds < ServerWaitSeconds {
		agreedWaitSeconds = to0d.WaitSeconds
	}

	err = h.ownersignDB.Save(ovHeader.OVGuid, ownerSign, agreedWaitSeconds)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	acceptOwner := fdoshared.AcceptOwner23{
		WaitSeconds: agreedWaitSeconds,
	}
	acceptOwnerBytes, _ := cbor.Marshal(acceptOwner)

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_23_ACCEPT_OWNER.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(acceptOwnerBytes)
}
