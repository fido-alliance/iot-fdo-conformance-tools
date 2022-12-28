package externalapi

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testexec"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	testdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/request"
	"github.com/gorilla/mux"
)

const DOSeedIDsBatchSize int = 20

type DOTestMgmtAPI struct {
	UserDB    *dbs.UserTestDB
	ReqTDB    *testdbs.RequestTestDB
	DevBaseDB *dbs.DeviceBaseDB
	SessionDB *dbs.SessionDB
	ConfigDB  *dbs.ConfigDB
}

func (h *DOTestMgmtAPI) checkAutzAndGetUser(r *http.Request) (*dbs.UserTestDBEntry, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, errors.New("Failed to read cookie. " + err.Error())

	}

	if sessionCookie == nil {
		return nil, errors.New("Cookie does not exists")
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return nil, errors.New("Session expired. " + err.Error())
	}

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *DOTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
	if !CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// Getting URL
	var createTestCase DOT_CreateTestCase
	err = json.Unmarshal(bodyBytes, &createTestCase)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	parsedUrl, err := url.ParseRequestURI(createTestCase.Url)
	if err != nil {
		log.Println("Bad URL. " + err.Error())
		RespondError(w, "Bad URL", http.StatusBadRequest)
		return
	}

	if parsedUrl.Path != "" && parsedUrl.Path != "/" {
		log.Println("Bad URL path.")
		RespondError(w, "Bad URL", http.StatusBadRequest)
		return
	}

	doUrl := parsedUrl.Scheme + "://" + parsedUrl.Host

	// Getting pre-gen config
	mainConfig, err := h.ConfigDB.Get()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// New request test instance
	newDOTTestTo2 := reqtestsdeps.NewRequestTestInst(doUrl, 2)

	// Generate test vouchers
	voucherTestBatch := mainConfig.SeededGuids.GetTestBatch(10000)

	var allTestIds fdoshared.FdoGuidList
	for _, v := range voucherTestBatch {
		allTestIds = append(allTestIds, v...)
	}

	voucherTestMap, err := testexec.GenerateTo2Vouchers(allTestIds, h.DevBaseDB)
	if err != nil {
		log.Println("Generate vouchers. " + err.Error())
		RespondError(w, "Failed to generate vouchers. Internal server error", http.StatusInternalServerError)
		return
	}

	newDOTTestTo2.TestVouchers = voucherTestMap
	newDOTTestTo2.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(DOSeedIDsBatchSize)

	// Saving stuff
	err = h.ReqTDB.Save(newDOTTestTo2)
	if err != nil {
		log.Println("Failed to save do test inst. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Saving user
	userInst.DOTestInsts = append(userInst.DOTestInsts, dbs.NewDOTestInst(doUrl, newDOTTestTo2.Uuid))
	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	RespondSuccess(w)
}

func (h *DOTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var dotList DOT_ListTestEntries = DOT_ListTestEntries{
		TestEntries: []DOT_Item{},
	}

	for _, dotInfo := range userInst.DOTestInsts {
		var dotItem DOT_Item = DOT_Item{
			Id:  hex.EncodeToString(dotInfo.Uuid),
			Url: dotInfo.Url,
		}

		dotsInfoPayloadPtr, err := h.ReqTDB.Get(dotInfo.To2)
		if err != nil {
			log.Println("Error reading dots. " + err.Error())
			RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		dotsInfoPayload := *dotsInfoPayloadPtr

		dotItem.To2 = DOT_InstInfo{
			Id:         hex.EncodeToString(dotsInfoPayload.Uuid),
			Runs:       dotsInfoPayload.TestsHistory,
			InProgress: dotsInfoPayload.InProgress,
			Protocol:   dotsInfoPayload.Protocol,
		}

		dotList.TestEntries = append(dotList.TestEntries, dotItem)

	}

	dotList.Status = FdoApiStatus_OK

	RespondSuccessStruct(w, dotList)
}

func (h *DOTestMgmtAPI) GetVouchers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	idBytes, err := hex.DecodeString(vars["uuid"])
	if err != nil {
		log.Printf("Cound not decode %s hex", vars["uuid"])
		RespondError(w, "ID not found!", http.StatusNotFound)
		return
	}

	if !userInst.DOT_ContainID(idBytes) {
		log.Printf("ID %s does not belong to user", vars["uuid"])
		RespondError(w, "ID not found!", http.StatusNotFound)
		return
	}

	dotsInfoPayloadPtr, err := h.ReqTDB.Get(idBytes)
	if err != nil {
		log.Println("Error reading dots. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	parsedUrl, err := url.ParseRequestURI(dotsInfoPayloadPtr.URL)
	if err != nil {
		log.Println("Bad URL. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var voucherList []fdoshared.DeviceCredAndVoucher
	for _, v := range dotsInfoPayloadPtr.TestVouchers {
		voucherList = append(voucherList, v...)
	}

	// Generate zip

	zipBuffer := new(bytes.Buffer)
	writer := zip.NewWriter(zipBuffer)

	for _, vanv := range voucherList {
		zipFile, err := writer.Create(fmt.Sprintf("%s.voucher.pem", hex.EncodeToString(vanv.WawDeviceCredential.DCGuid[:])))
		if err != nil {
			log.Println("Error creating new zip file instance. " + err.Error())
			RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		voucherPemBytes, err := fdodeviceimplementation.MarshalVoucherAndPrivateKey(vanv.VoucherDBEntry)
		if err != nil {
			log.Println("Error encoding voucher. " + err.Error())
			RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = zipFile.Write(voucherPemBytes)
		if err != nil {
			log.Println("Error writing zip file bytes. " + err.Error())
			RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	err = writer.Close()
	if err != nil {
		log.Println("Error closing zip stream. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.vouchers.zip\"", parsedUrl.Host))
	w.Write(zipBuffer.Bytes())
}

func (h *DOTestMgmtAPI) DeleteTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	receivedContentType := r.Header.Get("Content-Type")
	if receivedContentType != CONTENT_TYPE_JSON {
		RespondError(w, "Unsupported media types!", http.StatusUnsupportedMediaType)
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var execReq RVT_RequestInfo
	err = json.Unmarshal(bodyBytes, &execReq)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if len(execReq.TestRunId) == 0 {
		log.Println("Missing test run id field")
		RespondError(w, "Missing test run id field!", http.StatusBadRequest)
		return
	}

	rvtId, err := hex.DecodeString(execReq.Id)
	if err != nil {
		log.Println("Can not decode hex rvtid " + err.Error())
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.DOT_ContainID(rvtId) {
		log.Println("Id does not belong to user")
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	h.ReqTDB.RemoveTestRun(rvtId, execReq.TestRunId)

	RespondSuccess(w)
}

func (h *DOTestMgmtAPI) Execute(w http.ResponseWriter, r *http.Request) {
	if !CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var execReq RVT_RequestInfo
	err = json.Unmarshal(bodyBytes, &execReq)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	rvtId, err := hex.DecodeString(execReq.Id)
	if err != nil {
		log.Println("Can not decode hex rvtid " + err.Error())
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.RVT_ContainID(rvtId) {
		log.Println("Id does not belong to user")
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	rvte, err := h.ReqTDB.Get(rvtId)
	if err != nil {
		log.Println("Can get RVT entry. " + err.Error())
		RespondError(w, "Internal server error!", http.StatusBadRequest)
		return
	}

	testexec.ExecuteDOTestsTo2(*rvte, h.ReqTDB)

	RespondSuccess(w)
}
