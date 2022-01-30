package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"

	"github.com/WebauthnWorks/fdo-rv/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

const ServerWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type RvTo0 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
}

func (h *RvTo0) Handle20Hello(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving Hello20...")
	if !CheckHeaders(w, r, fdoshared.TO0_HELLO_20) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_HELLO_20, "Failed to read body!", http.StatusBadRequest)
		return
	}
	log.Println(bodyBytes)
	hex.EncodeToString(bodyBytes)
	bodyBytesAsString := string(bodyBytes)
	log.Println("As HexString:")
	log.Println((bodyBytesAsString))

	var helloMsg fdoshared.Hello20
	a, err := hex.DecodeString(bodyBytesAsString)

	err = cbor.Unmarshal(a, &helloMsg)
	if err != nil {
		log.Println("Some error")
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_HELLO_20, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	nonceTO0Sign := make([]byte, 16)
	rand.Read(nonceTO0Sign)

	newSessionInst := SessionEntry{
		Protocol:     fdoshared.To0,
		NonceTO0Sign: nonceTO0Sign,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_HELLO_20, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck := fdoshared.HelloAck21{
		NonceTO0Sign: nonceTO0Sign,
	}

	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_HELLO_ACK_21.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}

func (h *RvTo0) Handle22OwnerSign(w http.ResponseWriter, r *http.Request) {
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
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}

	if session.Protocol != fdoshared.To0 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Unauthorized (2)", http.StatusUnauthorized)
		return
	}

	/* ----- Process Body ----- */
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to read body!", http.StatusBadRequest)
		return
	}

	log.Println(bodyBytes)
	hex.EncodeToString(bodyBytes)
	bodyBytesAsString := string(bodyBytes)
	bodyBytesBuffer, err := hex.DecodeString(bodyBytesAsString)
	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to decode body 0!", http.StatusBadRequest)
		return
	}

	var ownerSign fdoshared.OwnerSign22
	err = cbor.Unmarshal(bodyBytesBuffer, &ownerSign)
	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to decode body 1!", http.StatusBadRequest)
		return
	}

	var to0d fdoshared.To0d
	err = cbor.Unmarshal(ownerSign.To0d, &to0d)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to decode body 2!", http.StatusBadRequest)
		return
	}

	var to1dPayload fdoshared.To1dBlobPayload
	err = cbor.Unmarshal(ownerSign.To1d.Payload, &to1dPayload)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to decode body 3!", http.StatusBadRequest)
		return
	}

	/* ----- Verify OwnerSign ----- */

	// Verify nonces

	if bytes.Compare(to0d.NonceTO0Sign[:], session.NonceTO0Sign[:]) != 0 {
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 1!", http.StatusBadRequest)
		return
	}

	// Verify voucher
	voucherIsValid, err := to0d.OwnershipVoucher.Validate()
	if err != nil {
		log.Println("OwnerSign22: Error verifying voucher. " + err.Error())

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 2!", http.StatusBadRequest)
		return
	}

	if !voucherIsValid {
		log.Println("OwnerSign22: Voucher is not valid")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 3!", http.StatusBadRequest)
		return
	}

	ovHeader, _ := to0d.OwnershipVoucher.GetOVHeader()

	// Verify To1D
	finalPublicKey, _ := to0d.OwnershipVoucher.GetFinalOwnerPublicKey()

	to1dIsValid, err := fdoshared.VerifyCoseSignature(ownerSign.To1d, finalPublicKey)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to1d. " + err.Error())

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 4!", http.StatusBadRequest)
		return
	}

	if !to1dIsValid {
		log.Println("OwnerSign22: To1D signature can not be validated!")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 5!", http.StatusBadRequest)
		return
	}

	// Verify To0D Hash
	to0dHashIsValid, err := fdoshared.VerifyHash(ownerSign.To0d, to1dPayload.To1dTo0dHash)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to0dHash. " + err.Error())

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 6!", http.StatusBadRequest)
		return
	}

	if !to0dHashIsValid {
		log.Println("OwnerSign22: To0d hash is not valid!")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Failed to validate owner sign 7!", http.StatusBadRequest)
		return
	}

	// Agreeing on timeout and saving
	agreedWaitSeconds := ServerWaitSeconds
	if to0d.WaitSeconds < ServerWaitSeconds {
		agreedWaitSeconds = to0d.WaitSeconds
	}

	err = h.ownersignDB.Save(ovHeader.OVGuid, ownerSign, agreedWaitSeconds)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_OWNER_SIGN_22, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	acceptOwner := fdoshared.AcceptOwner23{
		WaitSeconds: agreedWaitSeconds,
	}
	acceptOwnerBytes, _ := cbor.Marshal(acceptOwner)

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_ACCEPT_OWNER_23.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(acceptOwnerBytes)
}
