package rv

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/dgraph-io/badger/v4"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	tdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	listenertestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener"
)

type RvTo1 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
	listenerDB  *tdbs.ListenerTestDB
	ctx         context.Context
}

func NewRvTo1(db *badger.DB, ctx context.Context) RvTo1 {
	newListenerDb := tdbs.NewListenerTestDB(db)
	return RvTo1{
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

func (h *RvTo1) Handle30HelloRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloRV30...")

	var currentCmd fdoshared.FdoCmd = fdoshared.TO1_30_HELLO_RV

	var testcomListener *listenertestsdeps.RequestListenerInst
	if !fdoshared.CheckHeaders(w, r, currentCmd) {
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var helloRV30 fdoshared.HelloRV30
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &helloRV30)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err = h.listenerDB.GetEntryByFdoGuid(helloRV30.Guid)
	if err != nil {
		log.Printf("NO TEST CASE FOR %s. %s ", hex.EncodeToString(helloRV30.Guid[:]), err.Error())
	}

	if testcomListener != nil && !testcomListener.To1.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To1.CheckExpectedCmd(currentCmd) && testcomListener.To1.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To1.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To1.ExpectedCmd, currentCmd))
		} else if testcomListener.To1.CurrentTestIndex != 0 {
			testcomListener.To1.PushSuccess()
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To1.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To1)
			return
		}
	}

	_, err = h.ownersignDB.Get(helloRV30.Guid)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, currentCmd, "Could not find guid!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	nonceTO1Proof := fdoshared.NewFdoNonce()

	newSessionInst := SessionEntry{
		Protocol:      fdoshared.To1,
		NonceTO1Proof: nonceTO1Proof,
		Guid:          helloRV30.Guid,
		EASigInfo:     helloRV30.EASigInfo,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Internal Server Error!", http.StatusInternalServerError, testcomListener, fdoshared.To1)
		return
	}

	helloRVAck31 := fdoshared.HelloRVAck31{
		NonceTO1Proof: nonceTO1Proof,
		EBSigInfo:     helloRV30.EASigInfo,
	}

	helloRVAckBytes, _ := fdoshared.CborCust.Marshal(helloRVAck31)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_30_BAD_ENCODING {
		helloRVAckBytes = fdoshared.Conf_RandomCborBufferFuzzing(helloRVAckBytes)
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To1.CheckExpectedCmd(currentCmd) {
		testcomListener.To1.PushSuccess()
		testcomListener.To1.CompleteCmdAndSetNext(fdoshared.TO1_32_PROVE_TO_RV)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To1)
			return
		}
	}

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_31_HELLO_RV_ACK.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloRVAckBytes)
}

func (h *RvTo1) Handle32ProveToRV(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving ProveToRV32...")

	var currentCmd fdoshared.FdoCmd = fdoshared.TO1_32_PROVE_TO_RV

	var testcomListener *listenertestsdeps.RequestListenerInst
	if !fdoshared.CheckHeaders(w, r, currentCmd) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, currentCmd)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unauthorized", http.StatusUnauthorized, testcomListener, fdoshared.To1)
		return
	}

	if session.Protocol != fdoshared.To1 {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unauthorized", http.StatusUnauthorized, testcomListener, fdoshared.To1)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err = h.listenerDB.GetEntryByFdoGuid(session.Guid)
	if err != nil {
		log.Printf("NO TEST CASE FOR %s. %s ", hex.EncodeToString(session.Guid[:]), err.Error())
	}

	if testcomListener != nil && !testcomListener.To1.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To1.CheckExpectedCmd(currentCmd) && testcomListener.To1.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To1.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To1.ExpectedCmd, currentCmd))
		} else if testcomListener.To1.CurrentTestIndex != 0 {
			testcomListener.To1.PushSuccess()
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To1.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To1)
			return
		}
	}

	var proveToRV32 fdoshared.CoseSignature
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &proveToRV32)
	if err != nil {
		log.Println("Failed to decode proveToRV32 request: " + err.Error())
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var pb fdoshared.EATPayloadBase
	err = fdoshared.CborCust.Unmarshal(proveToRV32.Payload, &pb)
	if err != nil {
		log.Println("Failed to decode proveToRV32 payload: " + err.Error())
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode body payload!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	if !bytes.Equal(pb.EatNonce[:], session.NonceTO1Proof[:]) {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, fmt.Sprintf("EatNonce is not set to NonceTO1Proof. Expected %s. Got %s", hex.EncodeToString(pb.EatNonce[:]), hex.EncodeToString(session.NonceTO1Proof[:])), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// Get ownerSign from ownerSign storage
	savedOwnerSign, err := h.ownersignDB.Get(session.Guid)
	if err != nil {
		log.Println("Couldn't find item in database with guid" + err.Error())
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, "Server Error", http.StatusInternalServerError, testcomListener, fdoshared.To1)
		return
	}

	var to0d fdoshared.To0d
	err = fdoshared.CborCust.Unmarshal(savedOwnerSign.To0d, &to0d)
	if err != nil {
		log.Println("Error decoding To0d" + err.Error())

		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	pkType, ok := fdoshared.SgTypeToFdoPkType[session.EASigInfo.SgType]
	if !ok {
		log.Println("ProveToRV32: Unknown signature type. ")
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, "Error to verify signature ProveToRV32 ", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}
	err = fdoshared.VerifyCoseSignatureWithCertificate(proveToRV32, pkType, *to0d.OwnershipVoucher.OVDevCertChain)
	if err != nil {
		log.Println("ProveToRV32: Error verifying ProveToRV32 signature. " + err.Error())
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, "Error to verify signature ProveToRV32 ", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var to1d fdoshared.CoseSignature = savedOwnerSign.To1d
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_32_BAD_TO1D {
		to1d = fdoshared.Conf_Fuzz_CoseSignature(to1d)
	}

	rvRedirectBytes, _ := fdoshared.CborCust.Marshal(to1d)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_32_BAD_ENCODING {
		rvRedirectBytes = fdoshared.Conf_RandomCborBufferFuzzing(rvRedirectBytes)
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To1.PushSuccess()
		testcomListener.To1.CompleteTestRun()
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusInternalServerError, testcomListener, fdoshared.To1)
			return
		}
	}

	if fdoTestId == testcom.NULL_TEST && h.ctx.Value(fdoshared.CFG_ENV_INTEROP_ENABLED).(bool) {
		authzHeader, err := fdoshared.IopGetAuthz(h.ctx, fdoshared.IopRV)
		if err != nil {
			log.Println("IOT: Error getting authz header: " + err.Error())
		}

		err = fdoshared.SubmitIopLoggerEvent(h.ctx, session.Guid, fdoshared.To1, session.NonceTO1Proof, authzHeader)
		if err != nil {
			log.Println("IOT: Error sending iop logg event: " + err.Error())
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_33_RV_REDIRECT.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(rvRedirectBytes)
}
