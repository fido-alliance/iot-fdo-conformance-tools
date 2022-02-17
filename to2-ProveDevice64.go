package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) ProveDevice64(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving ProveDevice64...")

	if !CheckHeaders(w, r, fdoshared.TO2_PROVE_DEVICE_64) {
		return
	}

	headerIsOk, sessionId, _ := ExtractAuthorizationHeader(w, r, fdoshared.TO2_PROVE_DEVICE_64)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}

	bodyBytes2, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// DELETE
	hex.EncodeToString(bodyBytes2)
	bodyBytesAsString := string(bodyBytes2)
	bodyBytes, err := hex.DecodeString(bodyBytesAsString)
	// DELETE

	// voucher := session.Voucher

	var proveDevice64 fdoshared.ProveDevice64
	err = cbor.Unmarshal(bodyBytes, &proveDevice64)

	// voucher.OVDevCertChain
	var placeHolder_publicKey fdoshared.FdoPublicKey
	signatureIsValid, err := fdoshared.VerifyCoseSignature(proveDevice64, placeHolder_publicKey)
	if err != nil {
		log.Println("ProveDevice64: Error verigetInfo_response[GetInfoRespKeys.fying. " + err.Error())
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to verify signature ProveToRV32, some error", http.StatusBadRequest)
		return
	}

	if !signatureIsValid {
		log.Println("ProveDevice64: Signature is not valid!")
		RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to verify signature!", http.StatusBadRequest)
		return
	}

	var EATPayloadBase fdoshared.EATPayloadBase
	err = cbor.Unmarshal(proveDevice64.Payload, &EATPayloadBase)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	TO2ProveDevicePayload := EATPayloadBase.EatFDO.TO2ProveDevicePayload
	NonceTO2SetupDv := proveDevice64.Unprotected.CUPHNonce

	privateKeyBytes := session.PrivateKey

	var privateKey ecdsa.PrivateKey
	err = cbor.Unmarshal(privateKeyBytes, &privateKey)
	if err != nil {
		log.Println("Couldnt unmarshal privateKey")
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}
	// Finish KeyExchange
	shSeDO := finishKeyExchange(TO2ProveDevicePayload.XBKeyExchange, session.XAKeyExchange, privateKey, true)

	// @@@@@ KDF goes here!!! @@@@

	// store shSe in session here
	// sesion[]
	session.ShSeDO = shSeDO
	h.session.UpdateSessionEntry(sessionId, *session)

	// NonceTO2ProveDv := EATPayloadBase.EatNonce =>> this also goes in session for Done /70

	// TODO:
	TO2SetupDevicePayload := fdoshared.TO2SetupDevicePayload{
		RendezvousInfo:  []fdoshared.RendezvousInstrList{},
		Guid:            session.Guid,
		NonceTO2SetupDv: NonceTO2SetupDv,
		Owner2Key:       placeHolder_publicKey,
	}

	TO2SetupDevicePayloadBytes, err := cbor.Marshal(TO2SetupDevicePayload)

	var SetupDevice65 = fdoshared.SetupDevice65{
		Protected:   proveDevice64.Protected,
		Unprotected: proveDevice64.Unprotected,
		Payload:     TO2SetupDevicePayloadBytes,
		Signature:   nil,
	}

	SetupDeviceBytes, _ := cbor.Marshal(SetupDevice65)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_OV_NEXTENTRY_63.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(SetupDeviceBytes)

}
