package main

// import (
// 	"crypto/rand"
// 	"io/ioutil"
// 	"log"
// 	"net/http"

// 	"github.com/WebauthnWorks/fdo-do/fdoshared"
// 	"github.com/fxamacker/cbor/v2"
// )

// const agreedWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

// type DoTo2 struct {
// 	session       *SessionDB
// 	HelloDeviceDB *HelloDeviceDB
// }

// func (h *DoTo2) HelloDevice60(w http.ResponseWriter, r *http.Request) {
// 	log.Println("Receiving HelloDevice60...")
// 	if !CheckHeaders(w, r, fdoshared.TO0_HELLO_20) {
// 		return
// 	}

// 	bodyBytes, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to read body!", http.StatusBadRequest)
// 		return
// 	}

// 	var helloDevice fdoshared.HelloDevice60
// 	err = cbor.Unmarshal(bodyBytes, &helloDevice)
// 	if err != nil {
// 		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to decode body!", http.StatusBadRequest)
// 		return
// 	}

// 	// 1. Obtain voucher
// 	// 1a. Marshal OVHeader from voucher
// 	var voucher fdoshared.OwnershipVoucher
// 	OVHeaderBytes, _ := cbor.Marshal(voucher.OVHeader)

// 	// 2. Begin Key Exchange
// 	// Write code here.
// 	// xAKeyExchange, err := beginECDHKeyExchange(kexSuiteName)

// 	// 3. Generate Nonce
// 	NonceTO2ProveOV := make([]byte, 16)
// 	rand.Read(NonceTO2ProveOV)

// 	// 4. Encode response

// 	err = h.HelloDeviceDB.Save(helloDevice.Guid, helloDevice, agreedWaitSeconds)

// 	// Response:

// 	newSessionInst := SessionEntry{
// 		Protocol:        fdoshared.To2,
// 		NonceTO2ProveOV: helloDevice.NonceTO2ProveOV,
// 	}

// 	sessionId, err := h.session.NewSessionEntry(newSessionInst)
// 	if err != nil {
// 		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
// 		return
// 	}

// 	helloDeviceHash, err := fdoshared.GenerateFdoHash(bodyBytes, -16) // fix
// 	if err != nil {
// 		RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Internal Server Error!", http.StatusInternalServerError)
// 		return
// 	}

// 	proveOVHdrPayload := fdoshared.TO2ProveOVHdrPayload{
// 		OVHeader:            OVHeaderBytes,
// 		NumOVEntries:        255,                    // change
// 		HMac:                fdoshared.HashOrHmac{}, // Ownership Voucher "hmac" of hdr
// 		NonceTO2ProveOV:     helloDevice.NonceTO2ProveOV,
// 		EBSigInfo:           helloDevice.EASigInfo,
// 		XAKeyExchange:       "string", // Key exchange first step
// 		HelloDeviceHash:     helloDeviceHash,
// 		MaxOwnerMessageSize: helloDevice.MaxDeviceMessageSize, // change
// 	}

// 	proveOVHdrPayloadBytes, _ := cbor.Marshal(proveOVHdrPayload)

// 	helloAck, _ := fdoshared.GenerateCoseSignature(proveOVHdrPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, mfgPrivateKey, sgType)
// 	// fdoshared.ProveOVHdr61

// 	helloAckBytes, _ := cbor.Marshal(helloAck)

// 	sessionIdToken := "Bearer " + string(sessionId)
// 	w.Header().Set("Authorization", sessionIdToken)
// 	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
// 	w.Header().Set("Message-Type", fdoshared.TO0_HELLO_ACK_21.ToString())
// 	w.WriteHeader(http.StatusOK)
// 	w.Write(helloAckBytes)
// }

// // func (h *DoTo2) GetOVNextEntry62() (*fdoshared.OVNextEntry63, error) {
// // 	return nil, nil
// // }

// // func (h *DoTo2) ProveDevice64() (*fdoshared.SetupDevice65, error) {
// // 	log.Println("Receiving ProveDevice64...")
// // 	if !CheckHeaders(w, r, fdoshared.TO2_PROVE_DEVICE_64) {
// // 		return
// // 	}

// // 	bodyBytes, err := ioutil.ReadAll(r.Body)
// // 	if err != nil {
// // 		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to read body!", http.StatusBadRequest)
// // 		return
// // 	}

// // 	var helloDevice fdoshared.ProveDevice64
// // 	err = cbor.Unmarshal(bodyBytes, &helloDevice)
// // 	if err != nil {
// // 		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_PROVE_DEVICE_64, "Failed to decode body!", http.StatusBadRequest)
// // 		return
// // 	}
// // 	// 1. Validate nonce is same as in 61
// // 	// Decode
// // 	// 2. Complete exchange
// // 	// 3. Encode response
// // 	return nil, nil
// // }

// // func (h *DoTo2) DeviceServiceInfoReady66() (*fdoshared.OwnerServiceInfoReady67, error) {
// // 	return nil, nil
// // }

// // func (h *DoTo2) DeviceServiceInfo68() (*fdoshared.OwnerServiceInfo69, error) {
// // 	return nil, nil
// // }

// // func (h *DoTo2) Done70() (*fdoshared.Done271, error) {
// // 	return nil, nil
// // }

// // /**
// // /60
// // 1. Generate voucher
// // 2. Begin Key Exchange
// // 3. Generate Nonce
// // 4. Encode response

// // + stores items in db, set headers etc, generate auth token etc

// // /62
// // 1. Check previous entry, make sure this request is one entry higher
// // 2.
// // 3.
// // 4.

// // /64
// // 1. Validate nonce is same as in 61
// // 2. Complete exchange
// // 3. Encode response

// // /66
// // 1. Decrypt message
// // 2.
// // 3.

// // /68
// // 0. Decrypt message
// // 1. handleMaxDeviceServiceInfoSize
// // 2. handleCheckDevModKeys
// // 3. Encode response

// // /70
// // 0. Decrypt message
// // 1. Get NonceTO2SetupDv from db
// // 2. validateNonceDV (/70 = 61)
// // 3. Encode response

// // **/
