package main

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) GetOVNextEntry62(w http.ResponseWriter, r *http.Request) {

	log.Println("Receiving GetOVNextEntry...")
	if !CheckHeaders(w, r, fdoshared.TO2_GET_OVNEXTENTRY_62) {
		return
	}

	headerIsOk, sessionId, _ := ExtractAuthorizationHeader(w, r, fdoshared.TO2_GET_OVNEXTENTRY_62)
	if !headerIsOk {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Unauthorized (1)", http.StatusUnauthorized)
		return
	}
	if session.NextCmd != fdoshared.TO2_GET_OVNEXTENTRY_62 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Unauthorized. Didn't call /60 (1)", http.StatusUnauthorized)
		return
	}

	bodyBytes2, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Failed to read body!", http.StatusBadRequest)
		return
	}
	// DELETE
	hex.EncodeToString(bodyBytes2)
	bodyBytesAsString := string(bodyBytes2)
	bodyBytes, err := hex.DecodeString(bodyBytesAsString)
	// DELETE

	voucher := session.Voucher

	var getOVNextEntry fdoshared.GetOVNextEntry62
	err = cbor.Unmarshal(bodyBytes, &getOVNextEntry)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// check to see if LastOVEntryNum was never set, if so then the OVEntryNum must call 0
	if session.LastOVEntryNum == 0 && getOVNextEntry.GetOVNextEntry != 0 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "2 Error with OVEntryNum!", http.StatusBadRequest)
		return
	}

	if getOVNextEntry.GetOVNextEntry != 0 && getOVNextEntry.GetOVNextEntry != session.LastOVEntryNum+1 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "3 Error with OVEntryNum!", http.StatusBadRequest)
		return
	}

	// update OVEntryNum in session storage
	session.LastOVEntryNum = getOVNextEntry.GetOVNextEntry

	h.session.UpdateSessionEntry(sessionId, *session)

	if getOVNextEntry.GetOVNextEntry == session.NumOVEntries-1 {
		session.NextCmd = fdoshared.TO2_PROVE_DEVICE_64
		log.Println("next cmd is 64")
	} else {
		session.NextCmd = fdoshared.TO2_GET_OVNEXTENTRY_62
	}

	h.session.UpdateSessionEntry(sessionId, *session)

	// Needs fixing
	OVEntry := voucher.OVEntryArray[getOVNextEntry.GetOVNextEntry]

	var ovNextEntry63 = fdoshared.OVNextEntry63{
		OVEntryNum: getOVNextEntry.GetOVNextEntry,
		OVEntry:    OVEntry,
	}

	ovNextEntryBytes, _ := cbor.Marshal(ovNextEntry63)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_OV_NEXTENTRY_63.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ovNextEntryBytes)
}
