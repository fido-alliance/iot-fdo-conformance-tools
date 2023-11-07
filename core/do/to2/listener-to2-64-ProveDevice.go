package to2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	listenertestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/listener"
)

func (h *DoTo2) ProveDevice64(w http.ResponseWriter, r *http.Request) {
	log.Println("ProveDevice64: Receiving...")
	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_64_PROVE_DEVICE
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST

	session, sessionId, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndVerify(w, r, currentCmd)
	if err != nil {
		return
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(session.PrivateKeyDER)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Error decoding private key... "+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	// Test stuff

	if testcomListener != nil && !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To2.CheckExpectedCmd(currentCmd) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO2 %d. Got %d", testcomListener.To2.ExpectedCmd, currentCmd))
		} else if testcomListener.To2.CurrentTestIndex != 0 {
			testcomListener.To2.PushSuccess()
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(fdoshared.TO2_64_PROVE_DEVICE) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}

		for i := 0; i < int(session.NumOVEntries); i++ {
			if !session.Conf_RequestedOVEntriesContain(uint8(i)) {
				testcomListener.To2.PushFail(fmt.Sprintf("The %d OVEntry was never requested.", i))
			}
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	if session.PrevCMD != fdoshared.TO2_63_OV_NEXTENTRY {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected previous CMD to be %d. Got %d", fdoshared.TO2_63_OV_NEXTENTRY, session.PrevCMD), http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	// Verify CoseSignature
	var proveDevice64 fdoshared.CoseSignature
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &proveDevice64)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Error decoding request..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	pkType, ok := fdoshared.SgTypeToFdoPkType[session.EASigInfo.SgType]
	if !ok {
		log.Println("ProveToRV32: Unknown signature type. ")
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, "Error to verify signature ProveDevice64", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	err = fdoshared.VerifyCoseSignatureWithCertificate(proveDevice64, pkType, *session.Voucher.OVDevCertChain)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Error validating cose signature with certificate..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// EATPayload
	var eatPayload fdoshared.EATPayloadBase
	err = fdoshared.CborCust.Unmarshal(proveDevice64.Payload, &eatPayload)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Error decoding EATPayload..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// Verify Nonces
	if !bytes.Equal(eatPayload.EatNonce[:], session.NonceTO2ProveDv61[:]) {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, fmt.Sprintf("EatNonce is not set to NonceTO2ProveDv61. Expected %s. Got %s", hex.EncodeToString(eatPayload.EatNonce[:]), hex.EncodeToString(session.NonceTO2ProveDv61[:])), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// KEX
	sessionKey, err := fdoshared.DeriveSessionKey(session.XAKex, eatPayload.EatFDO.XBKeyExchange, false, privateKeyInst)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Error generating session shSe..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// ----- RESPONSE ----- //

	lastOvEntryPubKey, _ := session.Voucher.GetFinalOwnerPublicKey()

	ownerHeader, _ := session.Voucher.GetOVHeader()
	setupDevicePayload := fdoshared.TO2SetupDevicePayload{
		RendezvousInfo:  ownerHeader.OVRvInfo,
		Guid:            session.Guid,
		NonceTO2SetupDv: *proveDevice64.Unprotected.EUPHNonce,
		Owner2Key:       lastOvEntryPubKey,
	}

	session.NonceTO2SetupDv64 = *proveDevice64.Unprotected.EUPHNonce

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_NONCE_TO2SETUPDV {
		setupDevicePayload.NonceTO2SetupDv = fdoshared.NewFdoNonce()
	}

	setupDevicePayloadBytes, _ := fdoshared.CborCust.Marshal(setupDevicePayload)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_SETUPDEVICE_PAYLOAD {
		setupDevicePayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(setupDevicePayloadBytes)
	}

	// Response signature
	setupDevice, err := fdoshared.GenerateCoseSignature(setupDevicePayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, session.EASigInfo.SgType)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "ProveDevice64: Error generating setup device signature..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_SETUPDEVICE_COSE_SIGNATURE {
		tempSig := fdoshared.Conf_Fuzz_CoseSignature(*setupDevice)
		setupDevice = &tempSig
	}

	setupDeviceBytes, _ := fdoshared.CborCust.Marshal(setupDevice)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_SETUPDEVICE_BYTES {
		setupDeviceBytes = fdoshared.Conf_RandomCborBufferFuzzing(setupDeviceBytes)
	}

	// Response encrypted
	setupDeviceBytesEnc, err := fdoshared.AddEncryptionWrapping(setupDeviceBytes, *sessionKey, session.CipherSuiteName)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "ProveDevice64: Error encrypting..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_ENC_WRAPPING {
		setupDeviceBytesEnc, err = fdoshared.Conf_Fuzz_AddWrapping(setupDeviceBytesEnc, session.SessionKey, session.CipherSuiteName)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error encrypting..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
			return
		}
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_64_BAD_SETUPDEVICE_ENCODING {
		setupDeviceBytesEnc = fdoshared.Conf_RandomCborBufferFuzzing(setupDeviceBytesEnc)
	}

	// Update session
	session.SessionKey = *sessionKey
	session.PrevCMD = fdoshared.TO2_65_SETUP_DEVICE
	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "ProveDevice64: Error saving session..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To2.CheckExpectedCmd(currentCmd) {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteCmdAndSetNext(fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_65_SETUP_DEVICE.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(setupDeviceBytesEnc)
}
