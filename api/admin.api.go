package api

import (
	"log"
	"net/http"

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/services"
)

type AdminApi struct {
	UserDB        *dbs.UserTestDB
	VerifyDB      *dbs.VerifyDB
	NotifyService *services.NotifyService
}

func (h *AdminApi) GetUserList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

}

func (h *AdminApi) SetUserAccountState(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

}

func (h *AdminApi) EnableUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}
}
