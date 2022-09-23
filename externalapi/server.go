package externalapi

import (
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
)

func SetupServer(db *badger.DB) {
	userDb := dbs.NewUserTestDB(db)
	rvtDb := dbs.NewRequestTestDB(db)
	sessionDb := dbs.NewSessionDB(db)
	configDb := dbs.NewConfigDB(db)
	devBaseDb := dbs.NewDeviceBaseDB(db)

	rvtApiHandler := RVTestMgmtAPI{
		UserDB:    &userDb,
		ReqTDB:    &rvtDb,
		SessionDB: &sessionDb,
		ConfigDB:  &configDb,
		DevBaseDB: &devBaseDb,
	}

	dotApiHandler := DOTestMgmtAPI{
		UserDB:    &userDb,
		ReqTDB:    &rvtDb,
		SessionDB: &sessionDb,
		ConfigDB:  &configDb,
		DevBaseDB: &devBaseDb,
	}

	userApiHandler := UserAPI{
		UserDB:    &userDb,
		SessionDB: &sessionDb,
	}

	r := mux.NewRouter()

	r.HandleFunc("/api/rvt/create", rvtApiHandler.Generate)
	r.HandleFunc("/api/rvt/list", rvtApiHandler.List)
	r.HandleFunc("/api/rvt/list/testrun", rvtApiHandler.DeleteTestRun)
	r.HandleFunc("/api/rvt/execute", rvtApiHandler.Execute)

	r.HandleFunc("/api/dot/create", dotApiHandler.Generate)
	r.HandleFunc("/api/dot/list", dotApiHandler.List)
	r.HandleFunc("/api/dot/list/testrun", dotApiHandler.DeleteTestRun)
	r.HandleFunc("/api/dot/vouchers/{uuid}", dotApiHandler.GetVouchers)
	r.HandleFunc("/api/dot/execute", dotApiHandler.Execute)

	r.HandleFunc("/api/user/register", userApiHandler.Register)
	r.HandleFunc("/api/user/login", userApiHandler.Login)
	r.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)
	r.HandleFunc("/api/user/logout", userApiHandler.Logout)

	// r.Handle("/", http.FileServer(http.Dir("./_static")))
	r.PathPrefix("/").HandlerFunc(ProxyDevUI)

	http.Handle("/", r)

}
