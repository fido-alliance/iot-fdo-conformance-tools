package to2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/WebauthnWorks/fdo-shared/testcom"
	listenertestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/listener"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) Done70(w http.ResponseWriter, r *http.Request) {
	log.Println("Done70: Receiving...")

	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_70_DONE
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	session, _, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndDecrypt(w, r, currentCmd)
	if err != nil {
		return
	}

	// Test params setup
	if testcomListener != nil {
		if !testcomListener.To2.CheckExpectedCmd(currentCmd) {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To2.ExpectedCmd, currentCmd))
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}
	}

	if session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected previous CMD to be %d. Got %d", fdoshared.TO2_69_OWNER_SERVICE_INFO, session.PrevCMD), http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	var done70 fdoshared.Done70
	err = cbor.Unmarshal(bodyBytes, &done70)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Failed to decode Done70. "+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To2)

		log.Println("Done70: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if !bytes.Equal(done70.NonceTO2ProveDv[:], session.NonceTO2ProveDv61[:]) {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, fmt.Sprintf("EatNonce is not set to NonceTO2ProveDv61. Expected %s. Got %s", hex.EncodeToString(done70.NonceTO2ProveDv[:]), hex.EncodeToString(session.NonceTO2ProveDv61[:])), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	var done271Payload = fdoshared.Done271{
		NonceTO2SetupDv: session.NonceTO2SetupDv64,
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_70_BAD_NONCE_TO2SETUPDV64 {
		done271Payload.NonceTO2SetupDv = fdoshared.NewFdoNonce()
	}

	done271PayloadBytes, _ := cbor.Marshal(done271Payload)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_70_BAD_DONE71_ENCODING {
		done271PayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(done271PayloadBytes)
	}

	done271Bytes, err := fdoshared.AddEncryptionWrapping(done271PayloadBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Done70: Error encrypting..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To1)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_70_BAD_ENC_WRAPPING {
		done271Bytes, err = fdoshared.Conf_Fuzz_AddWrapping(done271PayloadBytes, session.SessionKey, session.CipherSuiteName)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Done70: Error encrypting..."+err.Error(), http.StatusInternalServerError, testcomListener, fdoshared.To1)
			return
		}
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteTestRun()
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To1)
			return
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_71_DONE2.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(done271Bytes)
}
