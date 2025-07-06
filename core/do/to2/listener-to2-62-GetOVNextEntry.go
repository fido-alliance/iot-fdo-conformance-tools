package to2

import (
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	listenertestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener"
)

func (h *DoTo2) GetOVNextEntry62(w http.ResponseWriter, r *http.Request) {
	log.Println("GetOVNextEntry62: Receiving...")
	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_62_GET_OVNEXTENTRY
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST

	var testcomListener *listenertestsdeps.RequestListenerInst
	if !fdoshared.CheckHeaders(w, r, currentCmd) {
		return
	}

	session, sessionId, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndVerify(w, r, currentCmd)
	if err != nil {
		return
	}

	if testcomListener != nil && !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To2.CheckExpectedCmd(currentCmd) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO2 %d. Got %d", testcomListener.To2.ExpectedCmd, currentCmd))
		} else if testcomListener.To2.CurrentTestIndex != 0 {
			testcomListener.To2.PushSuccess()
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result! "+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	if session.PrevCMD != fdoshared.TO2_61_PROVE_OVHDR && session.PrevCMD != fdoshared.TO2_63_OV_NEXTENTRY {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unexpected CMD...", http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	var getOVNextEntry fdoshared.GetOVNextEntry62
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &getOVNextEntry)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode GetOVNextEntry! "+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	if getOVNextEntry.GetOVNextEntry > session.NumOVEntries-1 {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "GetOVNextEntry is out of bound!", http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// Conformance
	session.Conf_AddOVEntryNum(getOVNextEntry.GetOVNextEntry)

	session.PrevCMD = fdoshared.TO2_63_OV_NEXTENTRY

	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error saving session...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	ovEntry := session.Voucher.OVEntryArray[getOVNextEntry.GetOVNextEntry]

	var ovNextEntry63 = fdoshared.OVNextEntry63{
		OVEntryNum: getOVNextEntry.GetOVNextEntry,
		OVEntry:    ovEntry,
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_62_BAD_OVENTRY_COSE_SIGNATURE {
		ovNextEntry63.OVEntry = fdoshared.Conf_Fuzz_CoseSignature(ovNextEntry63.OVEntry)
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_62_BAD_OVENTRYNUM {
		ovNextEntry63.OVEntryNum = uint8(fdoshared.NewRandomInt(int(ovNextEntry63.OVEntryNum)+1, 255))
	}

	ovNextEntryBytes, _ := fdoshared.CborCust.Marshal(ovNextEntry63)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_62_BAD_OVNEXTENTRY_PAYLOAD {
		ovNextEntryBytes = fdoshared.Conf_RandomCborBufferFuzzing(ovNextEntryBytes)
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To2.CheckExpectedCmd(currentCmd) {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteCmdAndSetNext(fdoshared.TO2_64_PROVE_DEVICE)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_63_OV_NEXTENTRY.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ovNextEntryBytes)
}
