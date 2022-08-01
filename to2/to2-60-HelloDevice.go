package to2

import (
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/dbs"
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

	// Getting cipher suit params
	cryptoParams, ok := fdoshared.CipherSuitesInfoMap[helloDevice.CipherSuiteName]
	if !ok {
		log.Println("HelloDevice60: Unknown cipher suit... ")
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Unknown cipher suit!", http.StatusBadRequest)
		return
	}

	// Getting voucher from DB
	voucherDBEntry, err := h.Voucher.Get(helloDevice.Guid)
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
	helloDeviceHash, _ := fdoshared.GenerateFdoHash(bodyBytes, cryptoParams.HmacAlg)

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

	newSessionInst := dbs.SessionEntry{
		Protocol:                 fdoshared.To2,
		PrevCMD:                  fdoshared.TO2_61_PROVE_OVHDR,
		NonceTO2ProveOV60:        helloDevice.NonceTO2ProveOV,
		PrivateKey:               voucherDBEntry.PrivateKeyX509,
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

	sessionId, err := h.Session.NewSessionEntry(newSessionInst)
	if err != nil {
		log.Println("HelloDevice60: Error saving session... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// 4. Encode response
	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)

	privateKeyInst, err := fdoshared.ExtractPrivateKey(voucherDBEntry.PrivateKeyX509)
	if err != nil {
		log.Println("HelloDevice60: Error decoding private key... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck, err := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, helloDevice.EASigInfo.SgType)
	if err != nil {
		log.Println("HelloDevice60: Error generating cose signature... " + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_60_HELLO_DEVICE, "Internal Server Error!", http.StatusInternalServerError)
		return
	}
	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_61_PROVE_OVHDR.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
