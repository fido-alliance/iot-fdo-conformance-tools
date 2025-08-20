package rv

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"

	"github.com/dgraph-io/badger/v4"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	tdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
)

const ServerWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type RvTo0 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
	listenerDB  *tdbs.ListenerTestDB
	ctx         context.Context
}

func NewRvTo0(db *badger.DB, ctx context.Context) RvTo0 {
	newListenerDb := tdbs.NewListenerTestDB(db)
	return RvTo0{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
		listenerDB: newListenerDb,
		ctx:        ctx,
	}
}

func (h *RvTo0) Handle20Hello(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving Hello20...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO0_20_HELLO) {
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var helloMsg fdoshared.Hello20

	err = fdoshared.CborCust.Unmarshal(bodyBytes, &helloMsg)
	if err != nil {
		log.Println("Error decoding Hello20. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	nonceTO0Sign := fdoshared.NewFdoNonce()

	newSessionInst := SessionEntry{
		Protocol:     fdoshared.To0,
		NonceTO0Sign: nonceTO0Sign,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_20_HELLO, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck := fdoshared.HelloAck21{
		NonceTO0Sign: nonceTO0Sign,
	}

	helloAckBytes, _ := fdoshared.CborCust.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_21_HELLO_ACK.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}

func (h *RvTo0) Handle22OwnerSign(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving OwnerSign22...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO0_22_OWNER_SIGN) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO0_22_OWNER_SIGN)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if session.Protocol != fdoshared.To0 {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Unauthorized", http.StatusUnauthorized)
		return
	}

	/* ----- Process Body ----- */
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_20_HELLO, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var ownerSign fdoshared.OwnerSign22
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &ownerSign)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	var to0d fdoshared.To0d
	err = fdoshared.CborCust.Unmarshal(ownerSign.To0d, &to0d)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	var to1dPayload fdoshared.To1dBlobPayload
	err = fdoshared.CborCust.Unmarshal(ownerSign.To1d.Payload, &to1dPayload)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Verify all the RVTO2AddrEntry
	for _, rvEntry := range to1dPayload.To1dRV {
		if rvEntry.RVDNS == nil && rvEntry.RVIP == nil {
			log.Println("OwnerSign22: Invalid RVTO2AddrEntry, both RVDNS and RVIP are nil!")
			fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
			return
		}
	}

	/* ----- Verify OwnerSign ----- */

	if !bytes.Equal(to0d.NonceTO0Sign[:], session.NonceTO0Sign[:]) {
		log.Println("OwnerSign22: NonceTO0Sign does not match!")
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	err = to0d.OwnershipVoucher.Validate()
	if err != nil {
		log.Println("OwnerSign22: Error verifying voucher. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate voucher!", http.StatusBadRequest)
		return
	}

	ovHeader, err := to0d.OwnershipVoucher.GetOVHeader()
	if err != nil {
		log.Println("OwnerSign22: Error decoding header. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	// Verify To1D
	finalPublicKey, err := to0d.OwnershipVoucher.GetFinalOwnerPublicKey()
	if err != nil {
		log.Println("OwnerSign22: Error decoding final owner public key. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign!", http.StatusBadRequest)
		return
	}

	err = fdoshared.VerifyCoseSignature(ownerSign.To1d, finalPublicKey)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to1d. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign 4!", http.StatusBadRequest)
		return
	}

	// Verify To0D Hash
	err = fdoshared.VerifyHash(ownerSign.To0d, to1dPayload.To1dTo0dHash)
	if err != nil {
		log.Println("OwnerSign22: Error verifying to0dHash. " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Failed to validate owner sign 6!", http.StatusBadRequest)
		return
	}

	// Agreeing on timeout and saving
	agreedWaitSeconds := ServerWaitSeconds
	if to0d.WaitSeconds < ServerWaitSeconds {
		agreedWaitSeconds = to0d.WaitSeconds
	}

	err = h.ownersignDB.Save(ovHeader.OVGuid, ownerSign, agreedWaitSeconds)
	if err != nil {
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO0_22_OWNER_SIGN, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	acceptOwner := fdoshared.AcceptOwner23{
		WaitSeconds: agreedWaitSeconds,
	}
	acceptOwnerBytes, _ := fdoshared.CborCust.Marshal(acceptOwner)

	iopEnabled := h.ctx.Value(fdoshared.CFG_ENV_INTEROP_ENABLED).(bool)
	// TODO: Add testid check
	if iopEnabled {
		authzHeader, err := fdoshared.IopGetAuthz(h.ctx, fdoshared.IopRV)
		if err != nil {
			log.Println("IOT: Error getting authz header: " + err.Error())
		}

		err = fdoshared.SubmitIopLoggerEvent(h.ctx, ovHeader.OVGuid, fdoshared.To0, session.NonceTO0Sign, authzHeader)
		if err != nil {
			log.Println("IOT: Error sending iop log event: " + err.Error())
		}
	} else if !iopEnabled {
		log.Println("Interop is not enabled, skipping IOP logger event submission")
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_23_ACCEPT_OWNER.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(acceptOwnerBytes)
}
