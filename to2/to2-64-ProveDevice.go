package to2

import (
	"bytes"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) ProveDevice64(w http.ResponseWriter, r *http.Request) {
	log.Println("ProveDevice64: Receiving...")

	session, sessionId, authorizationHeader, bodyBytes, err := h.receiveAndVerify(w, r, fdoshared.TO2_64_PROVE_DEVICE)
	if err != nil {
		return
	}

	if session.PrevCMD != fdoshared.TO2_63_OV_NEXTENTRY {
		log.Println("ProveDevice64: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify CoseSignature
	var proveDevice64 fdoshared.CoseSignature
	err = cbor.Unmarshal(bodyBytes, &proveDevice64)
	if err != nil {
		log.Println("ProveDevice64: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	err = fdoshared.VerifyCoseSignatureWithCertificate(proveDevice64, session.PublicKeyType, *session.Voucher.OVDevCertChain)
	if err != nil {
		log.Println("ProveDevice64: Error validating cose signature with certificate..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Error to verify cose signature!", http.StatusBadRequest)
		return
	}

	// EATPayload
	var eatPayload fdoshared.EATPayloadBase
	err = cbor.Unmarshal(proveDevice64.Payload, &eatPayload)
	if err != nil {
		log.Println("ProveDevice64: Error decoding EATPayload..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Verify Nonces
	if !bytes.Equal(eatPayload.EatNonce[:], session.NonceTO2ProveDv61[:]) {
		log.Println("ProveDevice64: Can not verify EatNonce vs NonceTO2ProveDv61...")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Failed to verify ProveDevice!", http.StatusBadRequest)
		return
	}

	// KEX
	sessionKey, err := fdoshared.DeriveSessionKey(&session.XAKex, eatPayload.EatFDO.XBKeyExchange, false)
	if err != nil {
		log.Println("ProveDevice64: Error generating session shSe..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Error for KEX!", http.StatusBadRequest)
		return
	}

	// ----- RESPONSE ----- //

	nonceTO2SetupDv := proveDevice64.Unprotected.EUPHNonce
	ownerHeader, _ := session.Voucher.GetOVHeader()
	setupDevicePayload := fdoshared.TO2SetupDevicePayload{
		RendezvousInfo:  []fdoshared.RendezvousInstrList{},
		Guid:            session.Guid,
		NonceTO2SetupDv: nonceTO2SetupDv,
		Owner2Key:       ownerHeader.OVPublicKey,
	}
	setupDevicePayloadBytes, _ := cbor.Marshal(setupDevicePayload)

	// Response signature
	privateKeyInst, err := fdoshared.ExtractPrivateKey(session.PrivateKeyDER)
	if err != nil {
		log.Println("HelloDevice60: Error decoding private key... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	setupDevice, err := fdoshared.GenerateCoseSignature(setupDevicePayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, session.SignatureType)
	if err != nil {
		log.Println("ProveDevice64: Error generating setup device signature..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	setupDeviceBytes, _ := cbor.Marshal(setupDevice)

	// Response encrypted
	setupDeviceBytesEnc, err := fdoshared.AddEncryptionWrapping(setupDeviceBytes, sessionKey, session.CipherSuiteName)
	if err != nil {
		log.Println("ProveDevice64: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	// Update session
	session.SessionKey = sessionKey
	session.PrevCMD = fdoshared.TO2_65_SETUP_DEVICE
	err = h.Session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		log.Println("ProveDevice64: Error saving session..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_64_PROVE_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_65_SETUP_DEVICE.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(setupDeviceBytesEnc)
}
