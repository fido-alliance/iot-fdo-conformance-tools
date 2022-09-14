package externalapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testexec"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

const FdoDOSeedIDsBatchSize int = 50

type DOTestMgmtAPI struct {
	UserDB    *dbs.UserTestDB
	ReqTDB    *dbs.RequestTestDB
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

	userInst, err := h.UserDB.Get(sessionInst.Username)
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

	mainConfig, err := h.ConfigDB.Get()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newDOTTestTo0 := req_tests_deps.NewRequestTestInst(doUrl, 0)
	newDOTTestTo0.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(FdoSeedIDsBatchSize)
	err = h.ReqTDB.Save(newDOTTestTo0)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newDotTestInst := dbs.NewDOTestInst(doUrl, newDOTTestTo0.Uuid)

	userInst.DOTestInsts = append(userInst.DOTestInsts, newDotTestInst)

	err = h.UserDB.Save(userInst.Username, *userInst)
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

		dotsInfoPayloadPtr, err := h.ReqTDB.Get(dotInfo.Uuid)
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

	if userInst.RVT_ContainID(rvtId) != nil {
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

	if userInst.RVT_ContainID(rvtId) != nil {
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

	if rvte.Protocol == fdoshared.To0 {
		testexec.ExecuteRVTestsTo0(*rvte, h.ReqTDB, h.DevBaseDB)
	} else if rvte.Protocol == fdoshared.To1 {
		testexec.ExecuteRVTestsTo1(*rvte, h.ReqTDB, h.DevBaseDB)
	} else {
		log.Printf("Protocol TO%d is not supported. ", rvte.Protocol)
		RespondError(w, "Unsupported protocol!", http.StatusBadRequest)
		return
	}

	RespondSuccess(w)
}
