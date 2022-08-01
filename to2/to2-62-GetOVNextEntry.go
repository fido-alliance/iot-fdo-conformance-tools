package to2

import (
	"io/ioutil"
	"log"
	"net/http"

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

	session, err := h.Session.GetSessionEntry(sessionId)
	if err != nil {
		log.Println("GetOVNextEntry62: Can not find session... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "Unauthorized", http.StatusInternalServerError)
		return
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
		log.Println("GetOVNextEntry62: Our of bound...")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_62_GET_OVNEXTENTRY, "GetOVNextEntry is out of bound!", http.StatusBadRequest)
		return
	}

	session.PrevCMD = fdoshared.TO2_63_OV_NEXTENTRY

	err = h.Session.UpdateSessionEntry(sessionId, *session)
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

	ovNextEntryBytes, _ := cbor.Marshal(ovNextEntry63)

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_63_OV_NEXTENTRY.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ovNextEntryBytes)
}
