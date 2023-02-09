package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/api/commonapi"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/services"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

const MAX_PASSWORD_RESET time.Duration = time.Hour

type UserVerify struct {
	UserDB        *dbs.UserTestDB
	VerifyDB      *dbs.VerifyDB
	SessionDB     *dbs.SessionDB
	NotifyService *services.NotifyService
}

func (h *UserVerify) getSession(r *http.Request) (*dbs.SessionEntry, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, err
	}

	if sessionCookie == nil {
		return nil, err
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return nil, err
	}

	return sessionInst, nil
}

func (h *UserVerify) deleteSession(r *http.Request) error {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return err
	}

	if sessionCookie == nil {
		return err
	}

	err = h.SessionDB.DeleteSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return err
	}

	return nil
}

func (h *UserVerify) generatePasswordHash(password string) ([]byte, error) {
	salt := make([]byte, 8)
	rand.Read(salt)

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return []byte{}, errors.New("error hashing password")
	}

	return append(salt, dk...), nil
}

func (h *UserVerify) Reject(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	email := vars["email"]

	entry, err := h.VerifyDB.GetEntry([]byte(id))
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Email != email {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	userInst, err := h.UserDB.Get(entry.Email)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Type != dbs.VT_User {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	userInst.Status = dbs.AS_Blocked

	err = h.UserDB.Save(*userInst)
	if err != nil {
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	err = h.VerifyDB.DeleteEntry([]byte(id))
	if err != nil {
		log.Println("Error deleting verify entry. " + err.Error())
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	err = h.NotifyService.NotifyUserRegistration_Rejected(userInst.Email, r.Context())
	if err != nil {
		log.Println("Error sending reject notification email. " + err.Error())
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserVerify) Check(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	email := vars["email"]

	entry, err := h.VerifyDB.GetEntry([]byte(id))
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Email != email {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	userInst, err := h.UserDB.Get(entry.Email)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Type == dbs.VT_Email {
		userInst.EmailVerified = true
	} else if entry.Type == dbs.VT_User {
		userInst.Status = dbs.AS_Validated
	} else {
		commonapi.RespondError(w, "Bad request!", http.StatusBadRequest)
		return
	}

	err = h.UserDB.Save(*userInst)
	if err != nil {
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	err = h.VerifyDB.DeleteEntry([]byte(id))
	if err != nil {
		log.Println("Error deleting verify entry. " + err.Error())
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserVerify) PasswordResetInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	// Decode body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Bad request!", http.StatusBadRequest)
		return
	}

	var userResetPasswordReq commonapi.User_ResetPasswordReq
	err = json.Unmarshal(bodyBytes, &userResetPasswordReq)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondSuccess(w)
		return
	}

	_, err = h.UserDB.Get(userResetPasswordReq.Email)
	if err != nil {
		log.Println("Failed to find user. " + err.Error())
		commonapi.RespondSuccess(w)
		return
	}

	err = h.NotifyService.NotifyUserRegistration_PasswordReset(userResetPasswordReq.Email, r.Context())
	if err != nil {
		log.Println("Failed to submit notification. " + err.Error())
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserVerify) PasswordResetCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	email := vars["email"]

	entry, err := h.VerifyDB.GetEntry([]byte(id))
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	userInst, err := h.UserDB.Get(entry.Email)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if userInst.Email != email {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Type != dbs.VT_PasswordReset {
		log.Println("Bad request. Entry type is not PasswordReset")
		commonapi.RespondError(w, "Bad request!", http.StatusBadRequest)
		return
	}

	sessionId, err := h.SessionDB.NewSessionEntry(dbs.SessionEntry{
		PasswordResetEmail:     userInst.Email,
		PasswordResetTimestamp: time.Now(),
	})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, commonapi.GenerateCookie(sessionId))

	err = h.VerifyDB.DeleteEntry([]byte(id))
	if err != nil {
		log.Println("Error deleting verify entry. " + err.Error())
		commonapi.RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/#/resetpassword/apply", http.StatusTemporaryRedirect)
}

func (h *UserVerify) PasswordResetSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	session, err := h.getSession(r)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if session.PasswordResetEmail == "" {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if session.PasswordResetTimestamp.Add(MAX_PASSWORD_RESET).Before(time.Now()) {
		err = h.deleteSession(r)
		if err != nil {
			log.Println("Error generating user hash. " + err.Error())
			commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
	}

	// Decode body

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var userResetPassword commonapi.User_ResetPassword
	err = json.Unmarshal(bodyBytes, &userResetPassword)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	// Add updated password

	userInst, err := h.UserDB.Get(session.PasswordResetEmail)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if len(userResetPassword.Password) < 6 || userResetPassword.Password != userResetPassword.ConfirmPassword {
		commonapi.RespondError(w, "Password is too short or does not match!", http.StatusBadRequest)
		return
	}

	passwordHash, err := h.generatePasswordHash(userResetPassword.Password)
	if err != nil {
		log.Println("Error generating user hash. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	userInst.PasswordHash = passwordHash

	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Error saving user. " + err.Error())
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	err = h.deleteSession(r)
	if err != nil {
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	sessionDbId, err := h.SessionDB.NewSessionEntry(dbs.SessionEntry{Email: userInst.Email, LoggedIn: true})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, commonapi.GenerateCookie(sessionDbId))
	commonapi.RespondSuccess(w)
}
