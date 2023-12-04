package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
)

func (h *UserAPI) OnPremNoLogin(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
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
