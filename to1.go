package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

type RvTo1 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
}

func (h *RvTo1) Handle30HelloRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloRV30...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO1_30_HELLO_RV) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_30_HELLO_RV, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var helloRV30 fdoshared.HelloRV30
	err = cbor.Unmarshal(bodyBytes, &helloRV30)

	if err != nil {
		log.Println(err)
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_30_HELLO_RV, "Failed to read body!", http.StatusBadRequest)
		return
	}

	_, err = h.ownersignDB.Get(helloRV30.Guid)
	if err != nil {
		log.Println(err)
		fdoshared.RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, fdoshared.TO1_30_HELLO_RV, "Could not find guid!", http.StatusBadRequest)
		return
	}

	nonceTO1Proof := fdoshared.NewFdoNonce()

	newSessionInst := SessionEntry{
		Protocol:      fdoshared.To1,
		NonceTO1Proof: nonceTO1Proof,
		Guid:          helloRV30.Guid,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO1_30_HELLO_RV, "Internal Server Error!", http.StatusInternalServerError)
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
	w.Header().Set("Message-Type", fdoshared.TO1_31_HELLO_RV_ACK.ToString())
	w.WriteHeader(http.StatusOK)

	w.Write(helloRVAckBytes)
}

func (h *RvTo1) Handle32ProveToRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving ProveToRV32...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO1_32_PROVE_TO_RV) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO1_32_PROVE_TO_RV)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if session.Protocol != fdoshared.To1 {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var proveToRV32 fdoshared.CoseSignature
	err = cbor.Unmarshal(bodyBytes, &proveToRV32)
	if err != nil {
		log.Println(err)
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	var pb fdoshared.EATPayloadBase
	err = cbor.Unmarshal(proveToRV32.Payload, &pb)
	if err != nil {
		log.Println(err)
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body payload!", http.StatusBadRequest)
		return
	}

	if !bytes.Equal(pb.EatNonce[:], session.NonceTO1Proof[:]) {
		log.Println("Nonce Invalid")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "NonceTo1Proof mismatch", http.StatusBadRequest)
		return
	}

	// Get ownerSign from ownerSign storage
	savedOwnerSign, err := h.ownersignDB.Get(session.Guid)
	if err != nil {
		log.Println("Couldn't find item in database with guid" + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Server Error", http.StatusInternalServerError)
		return
	}

	var to0d fdoshared.To0d
	err = cbor.Unmarshal(savedOwnerSign.To0d, &to0d)
	if err != nil {
		log.Println("Error decoding To0d" + err.Error())

		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	voucherHeader, err := to0d.OwnershipVoucher.GetOVHeader()
	if err != nil {
		log.Println("ProveToRV32: Error decoding OVHeader. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Error to verify signature ProveToRV32, some error", http.StatusBadRequest)
		return
	}

	err = fdoshared.VerifyCoseSignatureWithCertificate(proveToRV32, voucherHeader.OVPublicKey.PkType, *to0d.OwnershipVoucher.OVDevCertChain)
	if err != nil {
		log.Println("ProveToRV32: Error verifying ProveToRV32 signature. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Error to verify signature ProveToRV32, some error", http.StatusBadRequest)
		return
	}

	rvRedirectBytes, _ := cbor.Marshal(savedOwnerSign.To1d)

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_33_RV_REDIRECT.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(rvRedirectBytes)
}
