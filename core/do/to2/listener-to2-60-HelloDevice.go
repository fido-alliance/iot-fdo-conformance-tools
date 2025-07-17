package to2

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	listenertestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener"
)

func (h *DoTo2) HelloDevice60(w http.ResponseWriter, r *http.Request) {
	log.Println("HelloDevice60: Receiving...")
	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_60_HELLO_DEVICE

	var testcomListener *listenertestsdeps.RequestListenerInst
	if !fdoshared.CheckHeaders(w, r, currentCmd) {
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// Getting decoding device
	var helloDevice fdoshared.HelloDevice60
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &helloDevice)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to decode HelloDevice60!", http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, _ = h.listenerDB.GetEntryByFdoGuid(helloDevice.Guid)

	if testcomListener != nil && !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
		if !testcomListener.To2.CheckExpectedCmds([]fdoshared.FdoCmd{
			currentCmd,
			fdoshared.TO2_62_GET_OVNEXTENTRY,
		}) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO2 %d. Got %d", testcomListener.To2.ExpectedCmd, currentCmd))
		} else if testcomListener.To2.CurrentTestIndex != 0 {
			testcomListener.To2.PushSuccess()
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	// Getting voucher from DB
	voucherDBEntry, err := h.voucher.Get(helloDevice.Guid)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, currentCmd, "Can not find voucher.", http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	NonceTO2ProveDv := fdoshared.NewFdoNonce()

	// KEX Generation
	kex, err := fdoshared.GenerateXABKeyExchange(helloDevice.KexSuiteName, nil)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error generating XAKeyExchange...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	sgTypeInfo, ok := fdoshared.SgTypeInfoMap[helloDevice.EASigInfo.SgType]
	if !ok {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Unsupported sgType...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	// HelloDevice HASH
	helloDeviceHash, _ := fdoshared.GenerateFdoHash(bodyBytes, sgTypeInfo.HashType)

	voucherHeader, err := voucherDBEntry.Voucher.GetOVHeader()
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error parsing voucher header...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	// Generating response
	NumOVEntries := len(voucherDBEntry.Voucher.OVEntryArray)
	proveOVHdrPayload := fdoshared.TO2ProveOVHdrPayload{
		OVHeader:            voucherDBEntry.Voucher.OVHeaderTag,
		NumOVEntries:        uint8(NumOVEntries),
		HMac:                voucherDBEntry.Voucher.OVHeaderHMac, // Ownership Voucher "hmac" of hdr
		NonceTO2ProveOV:     helloDevice.NonceTO2ProveOV,
		EBSigInfo:           helloDevice.EASigInfo,
		XAKeyExchange:       kex.XAKeyExchange,
		HelloDeviceHash:     helloDeviceHash,
		MaxOwnerMessageSize: helloDevice.MaxDeviceMessageSize,
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_HELLODEVICEHASH {
		proveOVHdrPayload.HelloDeviceHash = *fdoshared.Conf_RandomTestHashHmac(proveOVHdrPayload.HelloDeviceHash, bodyBytes, []byte{})
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_NONCE_TO2PROVEOV {
		proveOVHdrPayload.NonceTO2ProveOV = fdoshared.NewFdoNonce()
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_EBSIGNINFO {
		proveOVHdrPayload.EBSigInfo.SgType = fdoshared.Conf_NewRandomSgTypeExcept(proveOVHdrPayload.EBSigInfo.SgType)
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_OVHDR_OVHEADER {
		proveOVHdrPayload.OVHeader = fdoshared.Conf_RandomCborBufferFuzzing(proveOVHdrPayload.OVHeader)
	}

	lastOwnerPubKey, err := voucherDBEntry.Voucher.GetFinalOwnerPublicKey()
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error getting last owner public key...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	proveOVHdrUnprotectedHeader := fdoshared.UnprotectedHeader{
		CUPHNonce:       &NonceTO2ProveDv,
		CUPHOwnerPubKey: &lastOwnerPubKey,
	}

	signatureSgType, ok := fdoshared.PkToSgType[lastOwnerPubKey.PkType]
	if !ok {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Unsupported pkType...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	newSessionInst := dbs.SessionEntry{
		Protocol: fdoshared.To2,
		PrevCMD:  fdoshared.TO2_61_PROVE_OVHDR,

		XAKex:        *kex,
		KexSuiteName: helloDevice.KexSuiteName,

		NonceTO2ProveOV60: helloDevice.NonceTO2ProveOV,
		NonceTO2ProveDv61: NonceTO2ProveDv,

		EASigInfo:       helloDevice.EASigInfo,
		PrivateKeyDER:   voucherDBEntry.PrivateKeyX509,
		CipherSuiteName: helloDevice.CipherSuiteName,
		PublicKeyType:   voucherHeader.OVPublicKey.PkType,
		SignatureSgType: signatureSgType,
		Guid:            helloDevice.Guid,
		Voucher:         voucherDBEntry.Voucher, // Stored twice in db, much more accessible from here

		NumOVEntries:             uint8(NumOVEntries),
		OwnerSIMsFinishedSending: false,
		OwnerSIMsSendCounter:     0,
		OwnerSIMs:                []fdoshared.ServiceInfoKV{},
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error saving session...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	proveOVHdrPayloadBytes, _ := fdoshared.CborCust.Marshal(proveOVHdrPayload)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_HELLOACK_PAYLOAD_ENCODING {
		proveOVHdrPayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(proveOVHdrPayloadBytes)
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(voucherDBEntry.PrivateKeyX509)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error decoding private key...", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	helloAck, err := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, proveOVHdrUnprotectedHeader, privateKeyInst, signatureSgType)
	if err != nil {
		log.Println("HelloDevice60: Error generating cose signature..." + err.Error())
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Error generating cose signature.", http.StatusInternalServerError, testcomListener, fdoshared.To2)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_COSE_SIGNATURE {
		fuzzedCoseSignature := fdoshared.Conf_Fuzz_CoseSignature(*helloAck)
		helloAck = &fuzzedCoseSignature
	}

	helloAckBytes, _ := fdoshared.CborCust.Marshal(helloAck)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_HELLOACK_ENCODING {
		helloAckBytes = fdoshared.Conf_RandomCborBufferFuzzing(helloAckBytes)
	}

	sessionIdToken := "Bearer " + string(sessionId)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_MISSING_AUTHZ_HEADER {
		sessionIdToken = ""
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To2.CheckExpectedCmd(currentCmd) {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteCmdAndSetNext(fdoshared.TO2_62_GET_OVNEXTENTRY)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_61_PROVE_OVHDR.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
