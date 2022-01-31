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
	hex.EncodeToString(bodyBytes)
	bodyBytesAsString := string(bodyBytes)
	bodyBytesBuffer, err := hex.DecodeString(bodyBytesAsString)

	var helloRV30 fdoshared.HelloRV30
	err = cbor.Unmarshal(bodyBytesBuffer, &helloRV30)

	if err != nil {
		log.Println(err)
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_HELLO_RV_30, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// TODO - check to see if GUID exists. (RESOURCE_NOT_FOUND if not)

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

	log.Println(helloRVAckBytes)
	log.Println("=========== nonce:")
	log.Println(nonceTO1Proof)
	// eg 8250ce8d4ec966491fdb1c49c2c66935a9fa822678244920616d206120706f7461746f652120536d6172742c20496f542c20706f7461746f6521
	// [h'CE8D4EC966491FDB1C49C2C66935A9FA', [-7, "I am a potatoe! Smart, IoT, potatoe!"]]

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
	hex.EncodeToString(bodyBytes)
	bodyBytesAsString := string(bodyBytes)
	bodyBytesBuffer, err := hex.DecodeString(bodyBytesAsString)

	var proveToRV32 fdoshared.ProveToRV32
	err = cbor.Unmarshal(bodyBytesBuffer, &proveToRV32)

	log.Println(bodyBytesBuffer)

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
	// TODO: Change == 0 > != 0
	if bytes.Compare(pb.EatNonce[:], session.NonceTO1Proof[:]) == 0 {
		log.Println("Nonce Invalid")
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "NonceTo1Proof mismatch", http.StatusBadRequest)
		return
	}

	// Extract guid for UEID
	var guid [16]byte
	copy(guid[:], pb.EatUEID[1:16])

	// Get ownerSign from to0 storage
	ownerSign22, err := h.ownersignDB.Get(guid)
	var ownershipVoucher fdoshared.OwnershipVoucher
	cbor.Unmarshal(ownerSign22.To0d, &ownershipVoucher)

	// Verify voucher => again?! Necssary or not?
	voucherIsValid, err := ownershipVoucher.Validate()

	if err != nil {
		log.Println("OwnerSign22: Error verifying voucher. " + err.Error())

		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to validate owner sign 2!", http.StatusBadRequest)
		return
	}

	if !voucherIsValid {
		log.Println("OwnerSign22: Voucher is not valid")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to validate owner sign 3!", http.StatusBadRequest)
		return
	}

	// Verify Signature is valid using =>
	// 5.4.3: "The signature is verified using the device certificate chain contained in the Ownership Voucher."
	signatureIsValid, err := fdoshared.VerifySignature(proveToRV32.Payload, proveToRV32.Signature, ownershipVoucher.OVDevCertChain, 10)
	if err != nil {
		log.Println("ProveToRV32: Error verifying. " + err.Error())
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to verify signature ProveToRV32, some error", http.StatusBadRequest)
		return
	}

	if !signatureIsValid {
		log.Println("ProveToRV32: Signature is not valid!")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_PROVE_TO_RV_32, "Failed to verify signature!", http.StatusBadRequest)
		return
	}

	log.Println(signatureIsValid)

	// check stored Nonce = NonceTO1Proof from helloRVAckBytes in Handle30HelloRV

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_RV_REDIRECT_33.ToString())
	w.WriteHeader(http.StatusOK)
	// w.Write(helloAckBytes)
}
