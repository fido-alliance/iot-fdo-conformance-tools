package testapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/testexec"
	fdoshared "github.com/fido-alliance/fdo-shared"
	testdbs "github.com/fido-alliance/fdo-shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/fdo-shared/testcom/request"
	"github.com/gorilla/mux"
)

const RVSeedIDsBatchSize int = 20

type RVTestMgmtAPI struct {
	UserDB    *dbs.UserTestDB
	ReqTDB    *testdbs.RequestTestDB
	DevBaseDB *dbs.DeviceBaseDB
	SessionDB *dbs.SessionDB
	ConfigDB  *dbs.ConfigDB
}

func (h *RVTestMgmtAPI) checkAutzAndGetUser(r *http.Request) (*dbs.UserTestDBEntry, error) {
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

func (h *RVTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
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

	var createTestCase RVT_CreateTestCase
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

	rvUrl := parsedUrl.Scheme + "://" + parsedUrl.Host

	mainConfig, err := h.ConfigDB.Get()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRVTestTo0 := reqtestsdeps.NewRequestTestInst(rvUrl, 0)
	newRVTestTo0.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(RVSeedIDsBatchSize)
	err = h.ReqTDB.Save(newRVTestTo0)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRVTestTo1 := reqtestsdeps.NewRequestTestInst(rvUrl, 1)
	newRVTestTo1.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(RVSeedIDsBatchSize)
	err = h.ReqTDB.Save(newRVTestTo1)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userInst.RVTestInsts = append(userInst.RVTestInsts, dbs.NewRVTestInst(rvUrl, newRVTestTo0.Uuid, newRVTestTo1.Uuid))

	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *RVTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
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

	var rvtsList RVT_ListRvts = RVT_ListRvts{
		RVTItems: []RVT_Item{},
	}

	for _, rvtInfo := range userInst.RVTestInsts {
		var rvtItem RVT_Item = RVT_Item{
			Id:  hex.EncodeToString(rvtInfo.Uuid),
			Url: rvtInfo.Url,
		}

		rvtsInfoPayloadsPtr, err := h.ReqTDB.GetMany([][]byte{rvtInfo.To0, rvtInfo.To1})
		if err != nil {
			log.Println("Error reading rvts. " + err.Error())
			commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		rvtsInfoPayloads := *rvtsInfoPayloadsPtr

		rvtItem.To0 = RVT_InstInfo{
			Id:         hex.EncodeToString(rvtsInfoPayloads[0].Uuid),
			Runs:       rvtsInfoPayloads[0].TestsHistory,
			InProgress: rvtsInfoPayloads[0].InProgress,
			Protocol:   rvtsInfoPayloads[0].Protocol,
		}

		rvtItem.To1 = RVT_InstInfo{
			Id:         hex.EncodeToString(rvtsInfoPayloads[1].Uuid),
			Runs:       rvtsInfoPayloads[1].TestsHistory,
			InProgress: rvtsInfoPayloads[1].InProgress,
			Protocol:   rvtsInfoPayloads[1].Protocol,
		}

		rvtsList.RVTItems = append(rvtsList.RVTItems, rvtItem)

	}

	rvtsList.Status = commonapi.FdoApiStatus_OK

	commonapi.RespondSuccessStruct(w, rvtsList)
}

func (h *RVTestMgmtAPI) DeleteTestRun(w http.ResponseWriter, r *http.Request) {
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

	rvtId, err := hex.DecodeString(testinsthex)
	if err != nil {
		log.Println("Can not decode hex rvtid " + err.Error())
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.RVT_ContainID(rvtId) {
		log.Println("Id does not belong to user")
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	h.ReqTDB.RemoveTestRun(rvtId, testrunid)

	commonapi.RespondSuccess(w)
}

func (h *RVTestMgmtAPI) Execute(w http.ResponseWriter, r *http.Request) {
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

	rvtId, err := hex.DecodeString(execReq.Id)
	if err != nil {
		log.Println("Can not decode hex rvtid " + err.Error())
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	if !userInst.RVT_ContainID(rvtId) {
		log.Println("Id does not belong to user")
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	rvte, err := h.ReqTDB.Get(rvtId)
	if err != nil {
		log.Println("Can get RVT entry. " + err.Error())
		commonapi.RespondError(w, "Internal server error!", http.StatusBadRequest)
		return
	}

	if rvte.Protocol == fdoshared.To0 {
		testexec.ExecuteRVTestsTo0(*rvte, h.ReqTDB, h.DevBaseDB)
	} else if rvte.Protocol == fdoshared.To1 {
		testexec.ExecuteRVTestsTo1(*rvte, h.ReqTDB, h.DevBaseDB)
	} else {
		log.Printf("Protocol TO%d is not supported. ", rvte.Protocol)
		commonapi.RespondError(w, "Unsupported protocol!", http.StatusBadRequest)
		return
	}

	commonapi.RespondSuccess(w)
}
