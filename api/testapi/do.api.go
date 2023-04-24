package testapi

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

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	fdodeviceimplementation "github.com/fido-alliance/fdo-fido-conformance-server/core/device"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	testdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/request"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/testexec"
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

	if !sessionInst.LoggedIn {
		return nil, errors.New("Unauthorized!")
	}

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *DOTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	// Getting URL
	var createTestCase DOT_CreateTestCase
	err = json.Unmarshal(bodyBytes, &createTestCase)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	parsedUrl, err := url.ParseRequestURI(createTestCase.Url)
	if err != nil {
		log.Println("Bad URL. " + err.Error())
		commonapi.RespondError(w, "Bad URL", http.StatusBadRequest)
		return
	}

	if parsedUrl.Path != "" && parsedUrl.Path != "/" {
		log.Println("Bad URL path.")
		commonapi.RespondError(w, "Bad URL", http.StatusBadRequest)
		return
	}

	doUrl := parsedUrl.Scheme + "://" + parsedUrl.Host

	// Getting pre-gen config
	mainConfig, err := h.ConfigDB.Get()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
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
		commonapi.RespondError(w, "Failed to generate vouchers. Internal server error", http.StatusInternalServerError)
		return
	}

	newDOTTestTo2.TestVouchers = voucherTestMap
	newDOTTestTo2.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(DOSeedIDsBatchSize)

	// Saving stuff
	err = h.ReqTDB.Save(newDOTTestTo2)
	if err != nil {
		log.Println("Failed to save do test inst. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Saving user
	userInst.DOTestInsts = append(userInst.DOTestInsts, dbs.NewDOTestInst(doUrl, newDOTTestTo2.Uuid))
	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *DOTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
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
			commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
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

	dotList.Status = commonapi.FdoApiStatus_OK

	commonapi.RespondSuccessStruct(w, dotList)
}

func (h *DOTestMgmtAPI) GetVouchers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	idBytes, err := hex.DecodeString(vars["uuid"])
	if err != nil {
		log.Printf("Cound not decode %s hex", vars["uuid"])
		commonapi.RespondError(w, "ID not found!", http.StatusNotFound)
		return
	}

	if !userInst.DOT_ContainID(idBytes) {
		log.Printf("ID %s does not belong to user", vars["uuid"])
		commonapi.RespondError(w, "ID not found!", http.StatusNotFound)
		return
	}

	dotsInfoPayloadPtr, err := h.ReqTDB.Get(idBytes)
	if err != nil {
		log.Println("Error reading dots. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	parsedUrl, err := url.ParseRequestURI(dotsInfoPayloadPtr.URL)
	if err != nil {
		log.Println("Bad URL. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
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
			commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		voucherPemBytes, err := fdodeviceimplementation.MarshalVoucherAndPrivateKey(vanv.VoucherDBEntry)
		if err != nil {
			log.Println("Error encoding voucher. " + err.Error())
			commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = zipFile.Write(voucherPemBytes)
		if err != nil {
			log.Println("Error writing zip file bytes. " + err.Error())
			commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	err = writer.Close()
	if err != nil {
		log.Println("Error closing zip stream. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.vouchers.zip\"", parsedUrl.Host))
	w.Write(zipBuffer.Bytes())
}

func (h *DOTestMgmtAPI) DeleteTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	testinsthex := vars["testinsthex"]
	testrunid := vars["testrunid"]

	dotId, err := hex.DecodeString(testinsthex)
	if err != nil {
		log.Println("Can not decode hex dotId " + err.Error())
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.DOT_ContainID(dotId) {
		log.Println("Id does not belong to user")
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	h.ReqTDB.RemoveTestRun(dotId, testrunid)

	commonapi.RespondSuccess(w)
}

func (h *DOTestMgmtAPI) Execute(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var execReq RVT_RequestInfo
	err = json.Unmarshal(bodyBytes, &execReq)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	dotId, err := hex.DecodeString(execReq.Id)
	if err != nil {
		log.Println("Can not decode hex dotId " + err.Error())
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.DOT_ContainID(dotId) {
		log.Println("Id does not belong to user")
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	rvte, err := h.ReqTDB.Get(dotId)
	if err != nil {
		log.Println("Can get RVT entry. " + err.Error())
		commonapi.RespondError(w, "Internal server error!", http.StatusBadRequest)
		return
	}

	testexec.ExecuteDOTestsTo2(*rvte, h.ReqTDB)

	commonapi.RespondSuccess(w)
}
