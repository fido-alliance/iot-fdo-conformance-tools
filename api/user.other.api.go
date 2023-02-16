package api

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/api/commonapi"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/services"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func (h *UserAPI) isLoggedIn(r *http.Request) (bool, *dbs.SessionEntry, *dbs.UserTestDBEntry) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		return false, nil, nil
	}

	if sessionCookie == nil {
		log.Println("Request missing session cookie!")
		return false, nil, nil
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		log.Println("Error reading session db!" + err.Error())
		return false, nil, nil
	}

	userInst, _ := h.UserDB.Get(sessionInst.Email)

	return sessionInst.LoggedIn, sessionInst, userInst
}

func (h *UserAPI) UserLoggedIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	isLoggedIn, _, _ := h.isLoggedIn(r)
	if isLoggedIn {
		commonapi.RespondSuccess(w)
	} else {
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (h *UserAPI) Config(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	commonapi.RespondSuccessStruct(w, commonapi.User_Config{
		Mode: fdoshared.CONFIG_MODE_TYPE(r.Context().Value(fdoshared.CFG_ENV_MODE).(string)),
	})
}

func (h *UserAPI) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	sessionCookie, err := r.Cookie("session")
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if sessionCookie == nil {
		log.Println("Request missing session cookie!")
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_, err = h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		log.Println("Error reading session db!" + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = h.SessionDB.DeleteSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		log.Println("Session does not exists.")
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, commonapi.GenerateCookie([]byte{}))

	commonapi.RespondSuccess(w)
}

func (h *UserAPI) PurgeTests(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	sessionCookie, err := r.Cookie("session")
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if sessionCookie == nil {
		log.Println("Request missing session cookie!")
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		log.Println("Error reading session db!" + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !sessionInst.LoggedIn {
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		log.Println("User does not exists.")
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userInst.DeviceTestInsts = []dbs.DeviceTestInst{}
	userInst.DOTestInsts = []dbs.DOTestInst{}
	userInst.RVTestInsts = []dbs.RVTestInst{}

	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Println("SUCCESSFULLY PURGED TESTS")

	commonapi.RespondSuccess(w)
}

func (h *UserAPI) ReRequestEmailValidationLink(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	isLoggedIn, session, _ := h.isLoggedIn(r)
	if isLoggedIn {
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
	}

	submissionCountry := commonapi.ExtractCloudflareLocation(r)

	err := h.Notify.NotifyUserRegistration_EmailVerification(session.Email, submissionCountry, r.Context())
	if err != nil {
		log.Println("Error sending user registration email. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserAPI) AdditionalInfo(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	_, session, _ := h.isLoggedIn(r)
	if session == nil || !session.OAuth2AdditionalInfo {
		log.Println("Session is empty!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var additonalInfo commonapi.User_UserReq
	err = json.Unmarshal(bodyBytes, &additonalInfo)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if len(additonalInfo.Name) == 0 {
		log.Println("Missing name!")
		commonapi.RespondError(w, "Missing name!", http.StatusBadRequest)
		return
	}

	if len(additonalInfo.Company) == 0 {
		log.Println("Missing company name!")
		commonapi.RespondError(w, "Missing company name!", http.StatusBadRequest)
		return
	}

	if len(additonalInfo.Phone) == 0 {
		log.Println("Missing phone number!")
		commonapi.RespondError(w, "Missing phone number!", http.StatusBadRequest)
		return
	}

	newUserInst := dbs.UserTestDBEntry{
		Email:   strings.ToLower(session.OAuth2Email),
		Name:    additonalInfo.Name,
		Company: additonalInfo.Company,
		Status:  dbs.AS_Awaiting,
	}

	err = h.UserDB.Save(newUserInst)
	if err != nil {
		log.Println("Error saving user. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	submissionCountry := commonapi.ExtractCloudflareLocation(r)

	err = h.Notify.NotifyUserRegistration_AccountValidation(newUserInst.Email, services.NotifyPayload{
		VendorEmail:   newUserInst.Email,
		VendorName:    additonalInfo.Name,
		VendorPhone:   additonalInfo.Phone,
		VendorCompany: additonalInfo.Company,
	}, submissionCountry, r.Context())
	if err != nil {
		log.Println("Error sending user verification email. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	commonapi.RespondError(w, "Your account pending approval. Once it approved you will receive notification on your email address.", http.StatusInternalServerError)
}
