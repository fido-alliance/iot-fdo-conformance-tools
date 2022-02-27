package main

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

const VOUCHERS_LOCATION string = "./_test_vouchers/"

type Voucher struct {
	session *SessionDB
}

func (h *Voucher) voucherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		h.saveVoucher(w, r)
	} else if r.Method == "DELETE" {
		h.deleteVoucherByGuid(w, r)
	} else if r.Method == "GET" {
		h.getVouchers(w, r)
	}
}

func (h *Voucher) register(w http.ResponseWriter, r *http.Request) {
	authToken, err := h.session.RegisterAuthToken()
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Authorization", authToken)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
	w.WriteHeader(http.StatusOK)
}

//  Can write some checking...
func (h *Voucher) deleteVoucherByGuid(w http.ResponseWriter, r *http.Request) {
	headerIsOk, authToken, _ := ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
	if !headerIsOk {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Header token invalid", http.StatusUnauthorized)
		return
	}
	authTokenBytes, _ := hex.DecodeString(string(authToken)) // TODO

	_, err := h.session.AuthTokenExists(authTokenBytes)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
		return
	}
	userInfo, err := h.session.GetAuthTokenInfo(authTokenBytes)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error. COuld not find user.", http.StatusBadRequest)
		return
	}

	guidToDelete := (r.URL.Query().Get("guid"))
	guidToDeleteBytes, _ := hex.DecodeString(string(guidToDelete)) // TODO

	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not find voucher using Guid", http.StatusBadRequest)
		return
	}

	deleted := false
	var newUserInfoGuidList []GuidToFileName
	for _, storedVoucherGuid := range userInfo.GuidList {
		if bytes.Compare(guidToDeleteBytes, storedVoucherGuid.Guid) == 0 {
			err := os.Remove(fmt.Sprint(TEST_VOUCHER_LOC, storedVoucherGuid.FileName, ".voucher.pem"))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
			deleted = true
		} else {
			newUserInfoGuidList = append(newUserInfoGuidList, storedVoucherGuid)
		}
	}
	userInfo.GuidList = newUserInfoGuidList
	err = h.session.UpdateTokenEntry(authTokenBytes, *userInfo)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error. Couldn't update vouchers", http.StatusBadRequest)
		return
	}

	if !deleted {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Voucher) getVouchers(w http.ResponseWriter, r *http.Request) {
	headerIsOk, authToken, _ := ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
	if !headerIsOk {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusUnauthorized)
		return
	}
	authTokenBytes, _ := hex.DecodeString(string(authToken)) // TODO

	_, err := h.session.AuthTokenExists(authTokenBytes)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
		return
	}
	userInfo, err := h.session.GetAuthTokenInfo(authToken)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
		return
	}
	var GuidsOnly []byte
	for _, storedVoucherGuid := range userInfo.GuidList {
		GuidsOnly = append(GuidsOnly, storedVoucherGuid.Guid...)
	}
	// Need to try with different guids
	GuidsOnlyBytes, err := cbor.Marshal(GuidsOnly)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
		return
	}

	w.Header().Set("Authorization", string(authToken))
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(GuidsOnlyBytes)
	// loop read through files based on userInfo.uuid
	// or get guid-file
}

func (h *Voucher) saveVoucher(w http.ResponseWriter, r *http.Request) {

	headerIsOk, authToken, _ := ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
	if !headerIsOk {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Header token invalid", http.StatusUnauthorized)
		return
	}

	_, err := h.session.AuthTokenExists(authToken)
	if err != nil {
		log.Println("Error here")
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
		return
	}

	voucherFileBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not read body", http.StatusBadRequest)
		return
	}

	// marshal and validate voucher file bytes
	voucherInst, err := validateVoucher(voucherFileBytes)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not validate voucher. Structure invalid.", http.StatusBadRequest)
		return
	}

	OVHeader, err := voucherInst.GetOVHeader()
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Coud not validate voucher - could not detect OVHeader.", http.StatusBadRequest)
		return
	}

	// Run hash checks on DevCertChain:
	// “OVDevCertChainHash” is the Hash of the concatenation of the contents of each byte string in “OwnershipVoucher.OVDevCertChain”,
	// in the presented order. When OVDevCertChain is CBOR null, OVDevCertChainHash is also CBOR null.
	// Outsource this
	var concatenationByteString []byte
	for _, bstr := range *voucherInst.OVDevCertChain {
		concatenationByteString = append(concatenationByteString, bstr...)
	}

	verifiedHash, err := fdoshared.VerifyHash(concatenationByteString, *OVHeader.OVDevCertChainHash)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !verifiedHash {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not verify hash", http.StatusBadRequest)
		return
	}

	// OVHeader.OVDevCertChainHash
	// Run hash checks on OVE => outsource this
	var lastOVEntry fdoshared.CoseSignature
	for i, OVEntry := range voucherInst.OVEntryArray {
		var OVEntryPayload fdoshared.OVEntryPayload
		err := cbor.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Error Veriyfing OVEntries", http.StatusInternalServerError)
			return
		}
		if i == 0 {
			var firstEntryHashContents []byte
			firstEntryHashContents = append(firstEntryHashContents, voucherInst.OVHeaderTag...)
			firstEntryHashContents = append(firstEntryHashContents, voucherInst.OVHeaderHMac.Hash...)
			fdoshared.VerifyHash(firstEntryHashContents, OVEntryPayload.OVEHashPrevEntry)
		} else {
			lastOVEntryBytes, err := cbor.Marshal(lastOVEntry)
			if err != nil {
				RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Error Veriyfing OVEntries", http.StatusInternalServerError)
				return
			}
			fdoshared.VerifyHash(lastOVEntryBytes, OVEntryPayload.OVEHashPrevEntry)
		}
		lastOVEntry = OVEntry
	}

	userInfo, err := h.session.GetAuthTokenInfo(authToken)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
		return
	}

	for _, storedVoucherGuid := range userInfo.GuidList {
		if bytes.Compare(storedVoucherGuid.Guid, OVHeader.OVGuid[:]) == 0 {
			RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Voucher Guid already stored", http.StatusBadRequest)
			return
		}
	}

	fileName := userInfo.UUID + "-" + fmt.Sprint(userInfo.Counter)
	userInfo.Counter++

	newGuidToFileName := GuidToFileName{
		Guid:     OVHeader.OVGuid[:],
		FileName: fileName,
	}
	userInfo.GuidList = append(userInfo.GuidList, newGuidToFileName)

	err = h.session.UpdateTokenEntry(authToken, *userInfo)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusBadRequest)
		return
	}

	// Make sure OVGuid has not occured on others... Check list of guids

	voucherWriteLocation := fmt.Sprintf("%s%s.voucher.pem", VOUCHERS_LOCATION, fileName)
	err = os.WriteFile(voucherWriteLocation, voucherFileBytes, 0644)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusBadRequest)
		return
	}

	log.Println("Successful Voucher Save")

}

func validateVoucher(voucherFileBytes []byte) (*fdoshared.OwnershipVoucher, error) {
	voucherBlock, rest := pem.Decode(voucherFileBytes)
	if voucherBlock == nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	if voucherBlock.Type != OWNERSHIP_VOUCHER_PEM_TYPE {
		return nil, errors.New("Detected bytes != actual length")
	}

	privateKeyBytes, rest := pem.Decode(rest)
	if privateKeyBytes == nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	// CBOR decode voucher

	var voucherInst fdoshared.OwnershipVoucher
	err := cbor.Unmarshal(voucherBlock.Bytes, &voucherInst)
	if err != nil {
		return nil, errors.New("Detected bytes != actual length")
	}

	return &voucherInst, nil
}
