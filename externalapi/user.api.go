package externalapi

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi/commonapi"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"golang.org/x/crypto/scrypt"
)

const ONPREM_CONFIG string = "tester@fido.local"

type UserAPI struct {
	UserDB    *dbs.UserTestDB
	SessionDB *dbs.SessionDB
}

func isEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(e)
}

func (h *UserAPI) generatePasswordHash(password string) ([]byte, error) {
	salt := make([]byte, 8)
	rand.Read(salt)

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return []byte{}, errors.New("Error hashing password")
	}

	return append(salt, dk...), nil
}

func (h *UserAPI) verifyPasswordHash(password string, passwordHash []byte) (bool, error) {
	salt := passwordHash[0:8]

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return false, errors.New("Error hashing password")
	}

	return bytes.Equal(append(salt, dk...), passwordHash), nil
}

func (h *UserAPI) Register(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_MODE) == fdoshared.CFG_MODE_ONPREM {
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

	_, err = h.UserDB.Get(createUser.Email)
	if err == nil {
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
		Username:     strings.ToLower(createUser.Email),
		PasswordHash: passwordHash,
		Name:         createUser.Name,
		Company:      createUser.Company,
		Phone:        createUser.Phone,
	}

	err = h.UserDB.Save(newUserInst.Username, newUserInst)
	if err != nil {
		log.Println("Error saving user. " + err.Error())
		commonapi.RespondError(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	sessionDbId, err := h.SessionDB.NewSessionEntry(dbs.SessionEntry{Username: createUser.Email})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, GenerateCookie(sessionDbId))
	RespondSuccess(w)
}

func (h *UserAPI) Login(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_MODE) == fdoshared.CFG_MODE_ONPREM {
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
		RespondError(w, "Invalid username or password", http.StatusBadRequest)
		commonapi.RespondError(w, "Invalid emails or password", http.StatusBadRequest)
		return
	}

	sessionDbId, err := h.SessionDB.NewSessionEntry(dbs.SessionEntry{Email: loginUser.Email})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, commonapi.GenerateCookie(sessionDbId))
	commonapi.RespondSuccess(w)
}

func (h *UserAPI) LoginOnPremNoLogin(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	if r.Context().Value(fdoshared.CFG_MODE) == fdoshared.CFG_MODE_ONLINE {
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

	sessionDbId, err := h.SessionDB.NewSessionEntry(dbs.SessionEntry{Email: ONPREM_CONFIG})
	if err != nil {
		log.Println("Error creating session. " + err.Error())
		commonapi.RespondError(w, "Internal server error. ", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, commonapi.GenerateCookie(sessionDbId))
	commonapi.RespondSuccess(w)
}

func (h *UserAPI) UserLoggedIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
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

	_, err = h.UserDB.Get(sessionInst.Email)
	if err != nil {
		log.Println("User does not exists.")
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *UserAPI) Config(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	commonapi.RespondSuccessStruct(w, commonapi.User_Config{
		Mode: r.Context().Value(fdoshared.CFG_MODE).(fdoshared.CONFIG_MODE_TYPE),
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
