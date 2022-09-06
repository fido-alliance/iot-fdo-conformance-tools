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
)

const FdoSeedIDsBatchSize int64 = 500

type RVTestMgmtAPI struct {
	UserDB    *dbs.UserTestDB
	ReqTDB    *dbs.RequestTestDB
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

	userInst, err := h.UserDB.Get(sessionInst.Username)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *RVTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
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

	var createTestCase RVT_CreateTestCase
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

	rvUrl := parsedUrl.Scheme + "://" + parsedUrl.Host

	mainConfig, err := h.ConfigDB.Get()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRVTestTo0 := req_tests_deps.NewRequestTestInst(rvUrl)
	newRVTestTo0.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(FdoSeedIDsBatchSize)
	err = h.ReqTDB.Save(newRVTestTo0)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRVTestTo1 := req_tests_deps.NewRequestTestInst(rvUrl)
	newRVTestTo1.FdoSeedIDs = mainConfig.SeededGuids.GetTestBatch(FdoSeedIDsBatchSize)
	err = h.ReqTDB.Save(newRVTestTo1)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userInst.RVTestInsts = []dbs.RVTestInst{
		{
			Url: rvUrl,
			To0: newRVTestTo0.Uuid,
			To1: newRVTestTo1.Uuid,
		},
	}

	err = h.UserDB.Save(userInst.Username, *userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	RespondSuccess(w)
}

func (h *RVTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
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

	var rvtsList RVT_ListRvts

	for _, rvtInfo := range userInst.RVTestInsts {
		var rvtItem RVT_Item

		rvtsInfoPayloadsPtr, err := h.ReqTDB.GetMany([][]byte{rvtInfo.To0, rvtInfo.To1})
		if err != nil {
			log.Println("Error reading rvts. " + err.Error())
			RespondError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		rvtsInfoPayloads := *rvtsInfoPayloadsPtr

		rvtItem.To0 = RVT_InstInfo{
			Id:         hex.EncodeToString(rvtsInfoPayloads[0].Uuid),
			Runs:       rvtsInfoPayloads[0].TestsHistory,
			InProgress: rvtsInfoPayloads[0].InProgress,
		}

		rvtItem.To1 = RVT_InstInfo{
			Id:         hex.EncodeToString(rvtsInfoPayloads[1].Uuid),
			Runs:       rvtsInfoPayloads[1].TestsHistory,
			InProgress: rvtsInfoPayloads[1].InProgress,
		}

		rvtsList.RVTItems = append(rvtsList.RVTItems, rvtItem)

	}

	rvtsList.Status = FdoApiStatus_OK

	RespondSuccessStruct(w, rvtsList)
}

func (h *RVTestMgmtAPI) Delete(w http.ResponseWriter, r *http.Request) {
	//TODO
}

func (h *RVTestMgmtAPI) Execute(w http.ResponseWriter, r *http.Request) {
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

	var execReq RVT_ExecureReq
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

	testexec.ExecuteRVTests(*rvte, h.ReqTDB, h.DevBaseDB)

	RespondSuccess(w)
}
