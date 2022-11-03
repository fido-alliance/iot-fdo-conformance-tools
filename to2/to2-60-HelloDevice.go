package to2

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *DoTo2) HelloDevice60(w http.ResponseWriter, r *http.Request) {
	log.Println("HelloDevice60: Receiving...")
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO2_60_HELLO_DEVICE) {
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("HelloDevice60: Error reading body... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// Getting decoding device
	var helloDevice fdoshared.HelloDevice60
	err = cbor.Unmarshal(bodyBytes, &helloDevice)
	if err != nil {
		log.Println("HelloDevice60: Error decoding request..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Test stuff
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST
	testcomListener, err := h.listenerDB.GetEntryByFdoGuid(helloDevice.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(helloDevice.Guid[:]), err.Error())
	}

	if testcomListener != nil {
		if !testcomListener.To2.CheckExpectedCmds([]fdoshared.FdoCmd{
			fdoshared.TO2_60_HELLO_DEVICE,
			fdoshared.TO2_62_GET_OVNEXTENTRY,
		}) {
			testcomListener.To2.PushFail(fmt.Sprintf("Expected TO1 %d. Got %d", testcomListener.To2.ExpectedCmd, fdoshared.TO2_60_HELLO_DEVICE))
		}

		if !testcomListener.To1.CheckCmdTestingIsCompleted(fdoshared.TO2_60_HELLO_DEVICE) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}
	}

	// Getting cipher suit params
	cryptoParams, ok := fdoshared.CipherSuitesInfoMap[helloDevice.CipherSuiteName]
	if !ok {
		log.Println("HelloDevice60: Unknown cipher suit... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Unknown cipher suit!", http.StatusBadRequest)
		return
	}

	// Getting voucher from DB
	voucherDBEntry, err := h.voucher.Get(helloDevice.Guid)
	if err != nil {
		log.Println("HelloDevice60: Error locating voucher..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.RESOURCE_NOT_FOUND, fdoshared.TO2_60_HELLO_DEVICE, "Can not find voucher.", http.StatusUnauthorized)
		return
	}

	NonceTO2ProveDv := fdoshared.NewFdoNonce()

	// KEX Generation
	kex, err := fdoshared.GenerateXAKeyExchange(helloDevice.KexSuiteName)
	if err != nil {
		log.Println("HelloDevice60: Error generating XAKeyExchange... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	// HelloDevice HASH
	helloDeviceHash, _ := fdoshared.GenerateFdoHash(bodyBytes, cryptoParams.HashAlg)

	voucherHeader, err := voucherDBEntry.Voucher.GetOVHeader()
	if err != nil {
		log.Println("HelloDevice60: Error parsing voucher header... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

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
		log.Println("HelloDevice60: Error getting last owner public key... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal server error!", http.StatusInternalServerError)
		return
	}

	proveOVHdrUnprotectedHeader := fdoshared.UnprotectedHeader{
		CUPHNonce:       NonceTO2ProveDv,
		CUPHOwnerPubKey: lastOwnerPubKey,
	}

	newSessionInst := dbs.SessionEntry{
		Protocol:                 fdoshared.To2,
		PrevCMD:                  fdoshared.TO2_61_PROVE_OVHDR,
		NonceTO2ProveOV60:        helloDevice.NonceTO2ProveOV,
		PrivateKeyDER:            voucherDBEntry.PrivateKeyX509,
		XAKex:                    *kex,
		NonceTO2ProveDv61:        NonceTO2ProveDv,
		KexSuiteName:             helloDevice.KexSuiteName,
		CipherSuiteName:          helloDevice.CipherSuiteName,
		SignatureType:            helloDevice.EASigInfo.SgType,
		PublicKeyType:            voucherHeader.OVPublicKey.PkType,
		Guid:                     helloDevice.Guid,
		NumOVEntries:             uint8(NumOVEntries),
		Voucher:                  voucherDBEntry.Voucher, // Stored twice in db, much more accessible from here
		OwnerSIMsFinishedSending: false,
		OwnerSIMsSendCounter:     0,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		log.Println("HelloDevice60: Error saving session... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_HELLOACK_PAYLOAD_ENCODING {
		proveOVHdrPayloadBytes = fdoshared.Conf_RandomCborBufferFuzzing(proveOVHdrPayloadBytes)
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(voucherDBEntry.PrivateKeyX509)
	if err != nil {
		log.Println("HelloDevice60: Error decoding private key... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck, err := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, proveOVHdrUnprotectedHeader, privateKeyInst, helloDevice.EASigInfo.SgType)
	if err != nil {
		log.Println("HelloDevice60: Error generating cose signature... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_COSE_SIGNATURE {
		fuzzedCoseSignature := fdoshared.Conf_Fuzz_CoseSignature(*helloAck)
		helloAck = &fuzzedCoseSignature
	}

	helloAckBytes, _ := cbor.Marshal(helloAck)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_BAD_HELLOACK_ENCODING {
		helloAckBytes = fdoshared.Conf_RandomCborBufferFuzzing(helloAckBytes)
	}

	sessionIdToken := "Bearer " + string(sessionId)
	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_60_MISSING_AUTHZ_HEADER {
		sessionIdToken = ""
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE {
		testcomListener.To2.CompleteCmd(fdoshared.TO2_60_HELLO_DEVICE)
	}

	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_61_PROVE_OVHDR.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
