package to2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) Done70(w http.ResponseWriter, r *http.Request) {
	log.Println("Done70: Receiving...")

	session, _, authorizationHeader, bodyBytes, err := h.receiveAndDecrypt(w, r, fdoshared.TO2_70_DONE)
	if err != nil {
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err := h.listenerDB.GetEntryByFdoGuid(session.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(session.Guid[:]), err.Error())
	}

	if testcomListener != nil {
		if !testcomListener.To2.CheckExpectedCmd(fdoshared.TO2_68_DEVICE_SERVICE_INFO) {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To2.ExpectedCmd, fdoshared.TO2_68_DEVICE_SERVICE_INFO))
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(fdoshared.TO2_68_DEVICE_SERVICE_INFO) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}
	}

	if session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		log.Println("Done70: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var done70 fdoshared.Done70
	err = cbor.Unmarshal(bodyBytes, &done70)
	if err != nil {
		log.Println("Done70: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if !bytes.Equal(done70.NonceTO2ProveDv[:], session.NonceTO2ProveDv61[:]) {
		log.Println("Done70: Can not verify NonceTO2ProveDv vs NonceTO2ProveDv61...")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_70_DONE, "Failed to verify Done70!", http.StatusBadRequest)
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
		log.Println("Done70: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_70_DONE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_70_BAD_ENC_WRAPPING {
		done271Bytes, err = fdoshared.Conf_Fuzz_AddWrapping(done271PayloadBytes, session.SessionKey, session.CipherSuiteName)
		if err != nil {
			log.Println("Done70: Error encrypting..." + err.Error())
			fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_70_DONE, "Internal server error!", http.StatusInternalServerError)
			return
		}
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To2.CompleteCmd(fdoshared.TO2_70_DONE)
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_71_DONE2.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(done271Bytes)
}
