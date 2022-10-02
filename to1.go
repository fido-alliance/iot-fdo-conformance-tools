package fdorv

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	tdbs "github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	listenertestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/listener_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type RvTo1 struct {
	session     *SessionDB
	ownersignDB *OwnerSignDB
	listenerDB  *tdbs.ListenerTestDB
}

func NewRvTo1(db *badger.DB) RvTo1 {
	newListenerDb := tdbs.NewListenerTestDB(db)
	return RvTo1{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
		listenerDB: newListenerDb,
	}
}

func (h *RvTo1) Handle30HelloRV(w http.ResponseWriter, r *http.Request) {
	var testcomListener *listenertestsdeps.RequestListenerInst
	log.Println("Receiving HelloRV30...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO1_30_HELLO_RV) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_30_HELLO_RV, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var helloRV30 fdoshared.HelloRV30
	err = cbor.Unmarshal(bodyBytes, &helloRV30)
	if err != nil {
		log.Println(err)
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_30_HELLO_RV, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err = h.listenerDB.Get(helloRV30.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(helloRV30.Guid[:]), err.Error())
	}

	if testcomListener != nil {
		if !testcomListener.To1.CheckExpectedCmd(fdoshared.TO1_30_HELLO_RV) {
			testcomListener.To1.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To1.ExpectedCmd, fdoshared.TO1_30_HELLO_RV))
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(fdoshared.TO1_30_HELLO_RV) {
			fdoTestId = testcomListener.To1.GetNextTestID()
		}
	}

	_, err = h.ownersignDB.Get(helloRV30.Guid)
	if err != nil {
		log.Println(err)
		Conf_RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, fdoshared.TO1_30_HELLO_RV, "Could not find guid!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	nonceTO1Proof := fdoshared.NewFdoNonce()

	newSessionInst := SessionEntry{
		Protocol:      fdoshared.To1,
		NonceTO1Proof: nonceTO1Proof,
		Guid:          helloRV30.Guid,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO1_30_HELLO_RV, "Internal Server Error!", http.StatusInternalServerError, testcomListener, fdoshared.To1)
		return
	}

	helloRVAck31 := fdoshared.HelloRVAck31{
		NonceTO1Proof: nonceTO1Proof,
		EBSigInfo:     helloRV30.EASigInfo,
	}

	helloRVAckBytes, _ := cbor.Marshal(helloRVAck31)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_30_BAD_ENCODING {
		helloRVAckBytes = fdoshared.Conf_RandomCborBufferFuzzing(helloRVAckBytes)
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To1.CompleteCmd(fdoshared.TO1_32_PROVE_TO_RV)
	}

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_31_HELLO_RV_ACK.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloRVAckBytes)
}

func (h *RvTo1) Handle32ProveToRV(w http.ResponseWriter, r *http.Request) {
	var testcomListener *listenertestsdeps.RequestListenerInst

	log.Println("Receiving ProveToRV32...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO1_32_PROVE_TO_RV) {
		return
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO1_32_PROVE_TO_RV)
	if !headerIsOk {
		return
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Unauthorized", http.StatusUnauthorized, testcomListener, fdoshared.To1)
		return
	}

	if session.Protocol != fdoshared.To1 {
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Unauthorized", http.StatusUnauthorized, testcomListener, fdoshared.To1)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err = h.listenerDB.Get(session.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(session.Guid[:]), err.Error())
	}

	if testcomListener != nil {
		if !testcomListener.To1.CheckExpectedCmd(fdoshared.TO1_32_PROVE_TO_RV) {
			testcomListener.To1.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To1.ExpectedCmd, fdoshared.TO1_32_PROVE_TO_RV))
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(fdoshared.TO1_32_PROVE_TO_RV) {
			fdoTestId = testcomListener.To1.GetNextTestID()
		}
	}

	var proveToRV32 fdoshared.CoseSignature
	err = cbor.Unmarshal(bodyBytes, &proveToRV32)
	if err != nil {
		log.Println(err)
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var pb fdoshared.EATPayloadBase
	err = cbor.Unmarshal(proveToRV32.Payload, &pb)
	if err != nil {
		log.Println(err)
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body payload!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	if !bytes.Equal(pb.EatNonce[:], session.NonceTO1Proof[:]) {
		log.Println("Nonce Invalid")
		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "NonceTo1Proof mismatch", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	// Get ownerSign from ownerSign storage
	savedOwnerSign, err := h.ownersignDB.Get(session.Guid)
	if err != nil {
		log.Println("Couldn't find item in database with guid" + err.Error())
		Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Server Error", http.StatusInternalServerError, testcomListener, fdoshared.To1)
		return
	}

	var to0d fdoshared.To0d
	err = cbor.Unmarshal(savedOwnerSign.To0d, &to0d)
	if err != nil {
		log.Println("Error decoding To0d" + err.Error())

		Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Failed to decode body!", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	voucherHeader, err := to0d.OwnershipVoucher.GetOVHeader()
	if err != nil {
		log.Println("ProveToRV32: Error decoding OVHeader. " + err.Error())
		Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Error to verify signature ProveToRV32, some error", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	err = fdoshared.VerifyCoseSignatureWithCertificate(proveToRV32, voucherHeader.OVPublicKey.PkType, *to0d.OwnershipVoucher.OVDevCertChain)
	if err != nil {
		log.Println("ProveToRV32: Error verifying ProveToRV32 signature. " + err.Error())
		Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, fdoshared.TO1_32_PROVE_TO_RV, "Error to verify signature ProveToRV32, some error", http.StatusBadRequest, testcomListener, fdoshared.To1)
		return
	}

	var to1d fdoshared.CoseSignature = savedOwnerSign.To1d
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_32_BAD_TO1D {
		to1d = fdoshared.Conf_Fuzz_CoseSignature(to1d)
	}

	rvRedirectBytes, _ := cbor.Marshal(to1d)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_32_BAD_ENCODING {
		rvRedirectBytes = fdoshared.Conf_RandomCborBufferFuzzing(rvRedirectBytes)
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO1_33_RV_REDIRECT.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(rvRedirectBytes)
}
