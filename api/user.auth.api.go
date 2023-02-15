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

func (h *UserAPI) Register(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var createUser commonapi.User_UserReq
	err = json.Unmarshal(bodyBytes, &createUser)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if !isEmailValid(createUser.Email) {
		log.Println("Invalid email!")
		commonapi.RespondError(w, "Invalid email!", http.StatusBadRequest)
		return
	}

	if len(createUser.Name) == 0 {
		log.Println("Missing name!")
		commonapi.RespondError(w, "Missing name!", http.StatusBadRequest)
		return
	}

	if len(createUser.Company) == 0 {
		log.Println("Missing company name!")
		commonapi.RespondError(w, "Missing company name!", http.StatusBadRequest)
		return
	}

	if len(createUser.Phone) == 0 {
		log.Println("Missing phone number!")
		commonapi.RespondError(w, "Missing phone number!", http.StatusBadRequest)
		return
	}

	if len(createUser.Password) < 8 {
		log.Println("Password too short!")
		commonapi.RespondError(w, "Password too short!", http.StatusBadRequest)
		return
	}

	userInst, err := h.UserDB.Get(createUser.Email)
	if err == nil && userInst.Status == dbs.AS_Awaiting {
		log.Println("User exists.")
		commonapi.RespondError(w, "User exists.", http.StatusBadRequest)
		return
	}

	passwordHash, err := h.generatePasswordHash(createUser.Password)
	if err != nil {
		log.Println("Error generating user hash. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	newUserInst := dbs.UserTestDBEntry{
		Email:        strings.ToLower(createUser.Email),
		PasswordHash: passwordHash,
		Name:         createUser.Name,
		Company:      createUser.Company,
		Status:       dbs.AS_Awaiting,
	}

	err = h.UserDB.Save(newUserInst)
	if err != nil {
		log.Println("Error saving user. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	submissionCountry := commonapi.ExtractCloudflareLocation(r)

	err = h.Notify.NotifyUserRegistration_EmailVerification(newUserInst.Email, submissionCountry, r.Context())
	if err != nil {
		log.Println("Error sending user registration email. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	err = h.Notify.NotifyUserRegistration_AccountValidation(newUserInst.Email, services.NotifyPayload{
		TargetEmail:   newUserInst.Email,
		VendorName:    newUserInst.Name,
		VendorPhone:   createUser.Phone,
		VendorCompany: newUserInst.Company,
	}, submissionCountry, r.Context())
	if err != nil {
		log.Println("Error sending user verification email. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	commonapi.RespondError(w, "Your account pending approval. Once it approved you will receive notification on your email address.", http.StatusInternalServerError)
}

func (h *UserAPI) Login(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var loginUser commonapi.User_UserReq
	err = json.Unmarshal(bodyBytes, &loginUser)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if !isEmailValid(loginUser.Email) {
		log.Println("Invalid email!")
		commonapi.RespondError(w, "Invalid email!", http.StatusBadRequest)
		return
	}

	userInst, err := h.UserDB.Get(loginUser.Email)
	if err != nil {
		log.Printf("Can not find user with email \"%s\". %s \n", loginUser.Email, err.Error())
		commonapi.RespondError(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	passwordMatch, err := h.verifyPasswordHash(loginUser.Password, userInst.PasswordHash)
	if err != nil {
		log.Println("Error while verifying hash of the password. " + err.Error())
		commonapi.RespondError(w, "Invalid emails or password", http.StatusBadRequest)
		return
	}

	if !passwordMatch {
		log.Println("Passwords do not match.")
		commonapi.RespondError(w, "Invalid emails or password", http.StatusBadRequest)
		return
	}

	if userInst.Status != dbs.AS_Validated {
		err := h.setUserSession(w, dbs.SessionEntry{
			Email: loginUser.Email,
		})
		if err != nil {
			log.Println("Error creating session. " + err.Error())
			commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
			return
		}

		commonapi.RespondError(w, "Your account pending approval. Please wait 2-3 working days. Otherwise email certification@fidoalliance.org", http.StatusBadRequest)
		return
	}

	err = h.setUserSession(w, dbs.SessionEntry{
		Email:    loginUser.Email,
		LoggedIn: true,
	})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserAPI) OnPremNoLogin(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONLINE {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	_, err := h.UserDB.Get(ONPREM_CONFIG)
	if err != nil {
		newUserInst := dbs.UserTestDBEntry{
			Email: strings.ToLower(ONPREM_CONFIG),
		}

		err = h.UserDB.Save(newUserInst)
		if err != nil {
			log.Println("Error saving user. " + err.Error())
			commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
	}

	err = h.setUserSession(w, dbs.SessionEntry{Email: ONPREM_CONFIG, LoggedIn: true})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	commonapi.RespondSuccess(w)
}
