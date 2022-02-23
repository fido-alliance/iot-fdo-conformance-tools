package main

import (
	"crypto/rand"
	"encoding/hex"
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
	Session       *SessionDB
	HelloDeviceDB *HelloDeviceDB
}

func (h *DoTo2) HelloDevice60(w http.ResponseWriter, r *http.Request) {
	log.Println("Receiving HelloDevice60...")
	if !CheckHeaders(w, r, fdoshared.TO2_HELLO_DEVICE_60) {
		return
	}

	// Unmarshal body
	bodyBytes2, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// DELETE
	hex.EncodeToString(bodyBytes2)
	bodyBytesAsString := string(bodyBytes2)
	bodyBytes, err := hex.DecodeString(bodyBytesAsString)
	// DELETE

	var helloDevice fdoshared.HelloDevice60
	err = cbor.Unmarshal(bodyBytes, &helloDevice)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Obtain stored voucher related to RV
	var storedVoucher StoredVoucher
	dbtxn := h.Session.db.NewTransaction(true)
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
	xAKeyExchange, privateKey := beginECDHKeyExchange(fdoshared.ECDH256)

	// Response:
	helloDeviceHash, err := fdoshared.GenerateFdoHash(bodyBytes, -16) // fix
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	NumOVEntries := len(storedVoucher.VoucherEntry.Voucher.OVEntryArray)
	if NumOVEntries > 255 {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	privateKeyBytes, err := fdoshared.MarshalPrivateKey(privateKey, -7) // TODO

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

	newSessionInst := SessionEntry{
		Protocol:          fdoshared.To2,
		NextCmd:           fdoshared.TO2_GET_OVNEXTENTRY_62,
		NonceTO2ProveOV:   helloDevice.NonceTO2ProveOV,
		PrivateKey:        privateKeyBytes,
		XAKeyExchange:     xAKeyExchange,
		NonceTO2ProveDv61: NonceTO2ProveDv,
		KexSuiteName:      helloDevice.KexSuiteName,
		CipherSuiteName:   helloDevice.CipherSuiteName,
		Guid:              helloDevice.Guid,
		NumOVEntries:      uint8(NumOVEntries),
		Voucher:           storedVoucher.VoucherEntry.Voucher, // Stored twice in db, much more accessible from here
	}

	sessionId, err := h.Session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// 4. Encode response
	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)

	privateKeyInst, err := fdoshared.ExtractPrivateKey(storedVoucher.VoucherEntry.PrivateKeyX509)

	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloAck, _ := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, helloDevice.EASigInfo.SgType)

	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
