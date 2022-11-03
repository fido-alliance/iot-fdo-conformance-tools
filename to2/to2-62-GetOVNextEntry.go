package to2

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) GetOVNextEntry62(w http.ResponseWriter, r *http.Request) {
	log.Println("GetOVNextEntry62: Receiving...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO2_62_GET_OVNEXTENTRY) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO2_62_GET_OVNEXTENTRY)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		log.Println("GetOVNextEntry62: Can not find session... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Unauthorized", http.StatusInternalServerError)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err := h.listenerDB.GetEntryByFdoGuid(session.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(session.Guid[:]), err.Error())
	}

	if testcomListener != nil {
		if !testcomListener.To2.CheckExpectedCmd(fdoshared.TO2_62_GET_OVNEXTENTRY) {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To2.ExpectedCmd, fdoshared.TO2_62_GET_OVNEXTENTRY))
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(fdoshared.TO2_62_GET_OVNEXTENTRY) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}
	}

	if session.PrevCMD != fdoshared.TO2_61_PROVE_OVHDR && session.PrevCMD != fdoshared.TO2_63_OV_NEXTENTRY {
		log.Println("GetOVNextEntry62: Unexpected CMD... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("GetOVNextEntry62: Error reading body... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var getOVNextEntry fdoshared.GetOVNextEntry62
	err = cbor.Unmarshal(bodyBytes, &getOVNextEntry)
	if err != nil {
		log.Println("GetOVNextEntry62: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if getOVNextEntry.GetOVNextEntry > session.NumOVEntries-1 {
		log.Println("GetOVNextEntry62: Out of bound...")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "GetOVNextEntry is out of bound!", http.StatusBadRequest)
		return
	}

	// Conformance
	session.Conf_AddOVEntryNum(getOVNextEntry.GetOVNextEntry)

	session.PrevCMD = fdoshared.TO2_63_OV_NEXTENTRY

	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		log.Println("GetOVNextEntry62: Error saving session..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Internal server error!", http.StatusInternalServerError)
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

	ovNextEntryBytes, _ := cbor.Marshal(ovNextEntry63)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_62_BAD_OVNEXTENTRY_PAYLOAD {
		ovNextEntryBytes = fdoshared.Conf_RandomCborBufferFuzzing(ovNextEntryBytes)
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To2.CompleteCmd(fdoshared.TO2_62_GET_OVNEXTENTRY)
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_63_OV_NEXTENTRY.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ovNextEntryBytes)
}
