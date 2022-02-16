package main

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

const agreedWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type DoTo2 struct {
	session       *SessionDB
	HelloDeviceDB *HelloDeviceDB
}

func (h *DoTo2) HelloDevice60(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloDevice60...")
	if !CheckHeaders(w, r, fdoshared.TO2_HELLO_DEVICE_60) {
		return
	}

	// Unmarshal body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var helloDevice fdoshared.HelloDevice60
	err = cbor.Unmarshal(bodyBytes, &helloDevice)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Obtain stored voucher related to RV
	options := badger.DefaultOptions("./badger.local.db")
	options.Logger = nil

	db, err := badger.Open(options)
	if err != nil {
		log.Panicln("Error opening Badger DB. " + err.Error())
	}
	defer db.Close()

	var storedVoucher StoredVoucher
	dbtxn := db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(helloDevice.Guid[:])
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed locating entry. The error is: "+err.Error(), http.StatusInternalServerError)
		return
	} else if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed locating entry. The error is: "+err.Error(), http.StatusInternalServerError)
		return
	}
	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed locating entry. The error is: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = cbor.Unmarshal(itemBytes, &storedVoucher)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed locating entry. The error is: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// END

	// Generate NonceTO2ProveDv61
	NonceTO2ProveDv := make([]byte, 16)
	rand.Read(NonceTO2ProveDv)

	// 2. Begin Key Exchange
	xAKeyExchange, privateKey := beginECDHKeyExchange(fdoshared.ECDH256) // _ => priva

	// Response:

	helloDeviceHash, err := fdoshared.GenerateFdoHash(bodyBytes, -16) // fix
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// helloDevice.Guid
	NumOVEntries := len(storedVoucher.VoucherEntry.Voucher.OVEntryArray)
	if NumOVEntries > 255 {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// store priva here using sessionId + nonce
	newSessionInst := SessionEntry{
		Protocol:          fdoshared.To2,
		NonceTO2ProveOV:   helloDevice.NonceTO2ProveOV,
		PrivateKey:        privateKey,
		NonceTO2ProveDv61: NonceTO2ProveDv,
		KexSuiteName:      helloDevice.KexSuiteName,
		CipherSuiteName:   helloDevice.CipherSuiteName,
		Guid:              helloDevice.Guid,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	proveOVHdrPayload := fdoshared.TO2ProveOVHdrPayload{
		OVHeader:            storedVoucher.VoucherEntry.Voucher.OVHeaderTag,
		NumOVEntries:        uint8(NumOVEntries),
		HMac:                storedVoucher.VoucherEntry.Voucher.OVHeaderHMac, // Ownership Voucher "hmac" of hdr
		NonceTO2ProveOV:     helloDevice.NonceTO2ProveOV,
		EBSigInfo:           helloDevice.EASigInfo,
		XAKeyExchange:       xAKeyExchange,
		HelloDeviceHash:     helloDeviceHash,
		MaxOwnerMessageSize: helloDevice.MaxDeviceMessageSize,
	}

	// 4. Encode response
	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)

	helloAck, _ := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, storedVoucher.VoucherEntry.PrivateKeyX509, helloDevice.EASigInfo.SgType)
	// fdoshared.ProveOVHdr61

	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
