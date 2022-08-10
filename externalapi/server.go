package externalapi

import (
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/dgraph-io/badger/v3"
)

func SetupServer(db *badger.DB) {
	userDb := dbs.NewUserTestDB(db)
	vdiDb := dbs.NewVDandVDB(db)
	rvtDb := dbs.NewRendezvousServerTestDB(db)
	sessionDb := dbs.NewSessionDB(db)

	rvtApiHandler := RVTestMgmtAPI{
		UserDB:    &userDb,
		VdiDB:     &vdiDb,
		RvtDB:     &rvtDb,
		SessionDB: &sessionDb,
	}

	userApiHandler := UserAPI{
		UserDB:    &userDb,
		SessionDB: &sessionDb,
	}

	http.HandleFunc("/api/rvt/create", rvtApiHandler.Generate)
	http.HandleFunc("/api/rvt/list", rvtApiHandler.List)

	http.HandleFunc("/api/user/register", userApiHandler.Register)
	http.HandleFunc("/api/user/login", userApiHandler.Login)
	http.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)

	http.Handle("/", http.FileServer(http.Dir("./_static")))
}
