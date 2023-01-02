package externalapi

import (
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi/commonapi"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

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
