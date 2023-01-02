package externalapi

import (
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi/commonapi"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/gorilla/mux"
)

type UserVerify struct {
	UserDB   *dbs.UserTestDB
	VerifyDB *dbs.VerifyDB
}

func (h *UserVerify) Check(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_MODE) == fdoshared.CFG_MODE_ONPREM {
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

	if entry.Type == dbs.VT_Email {
		userInst.EmailVerified = true
	} else if entry.Type == dbs.VT_User {
		userInst.AccountApproved = true
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
