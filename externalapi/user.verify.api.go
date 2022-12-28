package externalapi

import (
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/gorilla/mux"
)

type UserVerify struct {
	UserDB   *dbs.UserTestDB
	VerifyDB *dbs.VerifyDB
}

func (h *UserVerify) Check(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	email := vars["email"]

	entry, err := h.VerifyDB.GetEntry([]byte(id))
	if err != nil {
		RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	userInst, err := h.UserDB.Get(entry.Email)
	if err != nil {
		RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if userInst.Email != email {
		RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	if entry.Type == dbs.VT_Email {
		userInst.EmailVerified = true
	} else if entry.Type == dbs.VT_User {
		userInst.AccountApproved = true
	}

	err = h.UserDB.Save(*userInst)
	if err != nil {
		RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	err = h.VerifyDB.DeleteEntry([]byte(id))
	if err != nil {
		log.Println("Error deleting verify entry. " + err.Error())
		RespondError(w, "Internal Server Error!", http.StatusInternalServerError)
		return
	}

	RespondSuccess(w)
}
