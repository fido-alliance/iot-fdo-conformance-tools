package api

import (
	"net/http"

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
)

type ResultsAPI struct {
	UserDB    *dbs.UserTestDB
	SessionDB *dbs.SessionDB
}

func (h *ResultsAPI) Submit(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

}
