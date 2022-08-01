package main

import (
	"github.com/WebauthnWorks/fdo-do/dbs"
)

const VOUCHERS_LOCATION string = "./_test_vouchers/"

type Voucher struct {
	session *dbs.SessionDB
}

// func (h *Voucher) VoucherHandler(w http.ResponseWriter, r *http.Request) {
// 	if r.Method == "POST" {
// 		h.SaveVoucher(w, r)
// 	} else if r.Method == "DELETE" {
// 		h.DeleteVoucherByGuid(w, r)
// 	} else if r.Method == "GET" {
// 		h.GetVouchers(w, r)
// 	}
// }

// func (h *Voucher) Register(w http.ResponseWriter, r *http.Request) {
// 	authToken, err := h.session.RegisterAuthToken()
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusInternalServerError)
// 		return
// 	}
// 	w.Header().Set("Authorization", authToken)
// 	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
// 	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
// 	w.WriteHeader(http.StatusOK)
// }

// //  Can write some checking...
// func (h *Voucher) DeleteVoucherByGuid(w http.ResponseWriter, r *http.Request) {
// 	headerIsOk, authToken, _ := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
// 	if !headerIsOk {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Header token invalid", http.StatusUnauthorized)
// 		return
// 	}
// 	// authTokenBytes, _ := hex.DecodeString(string(authToken)) // TODO

// 	_, err := h.session.AuthTokenExists(authToken)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
// 		return
// 	}
// 	userInfo, err := h.session.GetAuthTokenInfo(authToken)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error. COuld not find user.", http.StatusBadRequest)
// 		return
// 	}

// 	guidToDelete := (r.URL.Query().Get("guid"))
// 	guidToDeleteBytes, _ := hex.DecodeString(string(guidToDelete)) // TODO

// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not find voucher using Guid", http.StatusBadRequest)
// 		return
// 	}

// 	deleted := false
// 	var newUserInfoGuidList []GuidToFileName
// 	for _, storedVoucherGuid := range userInfo.GuidList {
// 		if bytes.Compare(guidToDeleteBytes, storedVoucherGuid.Guid) == 0 {
// 			err := os.Remove(fmt.Sprint(TEST_VOUCHER_LOC, storedVoucherGuid.FileName, ".voucher.pem"))
// 			if err != nil {
// 				w.WriteHeader(http.StatusBadRequest)
// 			}
// 			deleted = true
// 		} else {
// 			newUserInfoGuidList = append(newUserInfoGuidList, storedVoucherGuid)
// 		}
// 	}
// 	userInfo.GuidList = newUserInfoGuidList
// 	err = h.session.UpdateTokenEntry(authToken, *userInfo)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error. Couldn't update vouchers", http.StatusBadRequest)
// 		return
// 	}

// 	if !deleted {
// 		w.WriteHeader(http.StatusBadRequest)
// 	} else {
// 		w.WriteHeader(http.StatusOK)
// 	}
// }

// func (h *Voucher) GetVouchers(w http.ResponseWriter, r *http.Request) {
// 	headerIsOk, authToken, _ := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
// 	if !headerIsOk {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusUnauthorized)
// 		return
// 	}

// 	_, err := h.session.AuthTokenExists(authToken)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
// 		return
// 	}
// 	userInfo, err := h.session.GetAuthTokenInfo(authToken)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
// 		return
// 	}
// 	var GuidsOnly []byte
// 	for _, storedVoucherGuid := range userInfo.GuidList {
// 		GuidsOnly = append(GuidsOnly, storedVoucherGuid.Guid...)
// 	}
// 	// Need to try with different guids
// 	GuidsOnlyBytes, err := cbor.Marshal(GuidsOnly)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Failed to read body!", http.StatusBadRequest)
// 		return
// 	}

// 	w.Header().Set("Authorization", string(authToken))
// 	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
// 	w.Header().Set("Message-Type", fdoshared.TO2_PROVE_OVHDR_61.ToString())
// 	w.WriteHeader(http.StatusOK)
// 	w.Write(GuidsOnlyBytes)
// 	// loop read through files based on userInfo.uuid
// 	// or get guid-file
// }

// func (h *Voucher) SaveVoucher(w http.ResponseWriter, r *http.Request) {

// 	headerIsOk, authToken, _ := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
// 	if !headerIsOk {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Header token invalid", http.StatusUnauthorized)
// 		return
// 	}

// 	_, err := h.session.AuthTokenExists(authToken)
// 	if err != nil {
// 		log.Println("Error here")
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
// 		return
// 	}

// 	voucherFileBytes, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not read body", http.StatusBadRequest)
// 		return
// 	}

// 	//  Validate cert bytes match ownershipVoucher struct
// 	voucherInst, err := fdoshared.ValidateVoucherStructFromCert(voucherFileBytes)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Could not validate voucher. Structure invalid.", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate ownershipVoucher is valid
// 	valid, OVHeader, err := voucherInst.Validate()
// 	if err != nil || !valid { // OK? TODO?
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Coud not validate voucher - could not detect OVHeader.", http.StatusBadRequest)
// 		return
// 	}

// 	userInfo, err := h.session.GetAuthTokenInfo(authToken)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Unauthorized. Bearer token is invalid", http.StatusBadRequest)
// 		return
// 	}

// 	for _, storedVoucherGuid := range userInfo.GuidList {
// 		if bytes.Compare(storedVoucherGuid.Guid, OVHeader.OVGuid[:]) == 0 {
// 			fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Voucher Guid already stored", http.StatusBadRequest)
// 			return
// 		}
// 	}
// 	GuidToFileName
// 	fileName := userInfo.UUID + "-" + fmt.Sprint(userInfo.Counter)
// 	userInfo.Counter++

// 	newGuidToFileName := GuidToFileName{
// 		Guid:     OVHeader.OVGuid[:],
// 		FileName: fileName,
// 	}
// 	userInfo.GuidList = append(userInfo.GuidList, newGuidToFileName)

// 	err = h.session.UpdateTokenEntry(authToken, *userInfo)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusBadRequest)
// 		return
// 	}

// 	// Make sure OVGuid has not occured on others... Check list of guids

// 	voucherWriteLocation := fmt.Sprintf("%s%s.voucher.pem", VOUCHERS_LOCATION, fileName)
// 	err = os.WriteFile(voucherWriteLocation, voucherFileBytes, 0644)
// 	if err != nil {
// 		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.VOUCHER_API, "Internal Server Error", http.StatusBadRequest)
// 		return
// 	}

// 	log.Println("Successful Voucher Save")

// }
