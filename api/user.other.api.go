package api

import (
	"log"
	"net/http"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api/commonapi"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"
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
		// log.Println("Error reading session db!" + err.Error())
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
		// log.Println("Error reading session db!" + err.Error())
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
		// log.Println("Error reading session db!" + err.Error())
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
