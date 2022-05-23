package to2

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
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
	if !CheckHeaders(w, r, fdoshared.TO0_HELLO_20) {
		return
	}

	options := badger.DefaultOptions("./badger.local.db")
	options.Logger = nil

	db, err := badger.Open(options)
	if err != nil {
		log.Panicln("Error opening Badger DB. " + err.Error())
	}
	defer db.Close()

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

	// 1. Obtain voucher
	// 1a. Marshal OVHeader from voucher
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

	// 2. Begin Key Exchange
	// Write code here.
	// xAKeyExchange, err := beginECDHKeyExchange(kexSuiteName)

	// 3. Generate Nonce
	NonceTO2ProveOV := make([]byte, 16)
	rand.Read(NonceTO2ProveOV)

	// 4. Encode response

	err = h.HelloDeviceDB.Save(helloDevice.Guid, helloDevice, agreedWaitSeconds)

	// Response:

	newSessionInst := SessionEntry{
		Protocol:        fdoshared.To2,
		NonceTO2ProveOV: helloDevice.NonceTO2ProveOV,
	}

	sessionId, err := h.session.NewSessionEntry(newSessionInst)
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	helloDeviceHash, err := fdoshared.GenerateFdoHash(bodyBytes, -16) // fix
	if err != nil {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	// NonceTO2ProveDv61
	// store NonceTO2ProveDv61

	// helloDevice.Guid
	var NumOVEntries int
	NumOVEntries = len(storedVoucher.VoucherEntry.Voucher.OVEntryArray)
	if NumOVEntries > 255 {
		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	xAKeyExchange, _ := beginECDHKeyExchange(fdoshared.ECDH256) // _ => priva
	// store priva here

	proveOVHdrPayload := fdoshared.TO2ProveOVHdrPayload{
		OVHeader:            storedVoucher.VoucherEntry.Voucher.OVHeaderTag,
		NumOVEntries:        uint8(NumOVEntries),                             // change
		HMac:                storedVoucher.VoucherEntry.Voucher.OVHeaderHMac, // Ownership Voucher "hmac" of hdr
		NonceTO2ProveOV:     helloDevice.NonceTO2ProveOV,
		EBSigInfo:           helloDevice.EASigInfo,
		XAKeyExchange:       xAKeyExchange, // Key exchange first step
		HelloDeviceHash:     helloDeviceHash,
		MaxOwnerMessageSize: helloDevice.MaxDeviceMessageSize, // change
	}

	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)

	helloAck, _ := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, storedVoucher.VoucherEntry.PrivateKeyX509, helloDevice.EASigInfo.SgType)
	// fdoshared.ProveOVHdr61

	helloAckBytes, _ := cbor.Marshal(helloAck)

	sessionIdToken := "Bearer " + string(sessionId)
	w.Header().Set("Authorization", sessionIdToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO0_HELLO_ACK_21.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(helloAckBytes)
}
