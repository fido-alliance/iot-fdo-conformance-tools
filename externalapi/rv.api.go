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
	"github.com/WebauthnWorks/fdo-fido-conformance-server/rvtests"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

type RVTestMgmtAPI struct {
	UserDB    *dbs.UserTestDB
	RvtDB     *dbs.RendezvousServerTestDB
	SessionDB *dbs.SessionDB
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

	vdis, err := testcom.GenerateTestVoucherSet()
	if err != nil {
		log.Println("Failed to generate VDIs. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newRVTest := rvtests.NewRVDBTestEntry(parsedUrl.Scheme + "://" + parsedUrl.Hostname())
	newRVTest.VDIs = vdis

	err = h.RvtDB.Save(newRVTest)
	if err != nil {
		log.Println("Failed to save rvte. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userInst.RVTInsts = append(userInst.RVTInsts, newRVTest.ID)

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

	rvts, err := h.RvtDB.GetMany(userInst.RVTInsts)
	if err != nil {
		log.Println("Error reading rvts. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var rvtsList RVT_ListRvts
	rvtsList.Rvts = make([]RVT_Inst, 0)
	for _, rvt := range *rvts {
		rvtsList.Rvts = append(rvtsList.Rvts, RVT_Inst{
			Id:  hex.EncodeToString(rvt.ID),
			Url: rvt.URL,
		})
	}
	rvtsList.Status = FdoApiStatus_OK

	RespondSuccessStruct(w, rvtsList)
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

	if !userInst.ContainsRVT(rvtId) {
		log.Println("Id does not belong to user")
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	RespondSuccess(w)
}
