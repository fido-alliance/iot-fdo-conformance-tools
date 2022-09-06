package externalapi

import (
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/dgraph-io/badger/v3"
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

	userApiHandler := UserAPI{
		UserDB:    &userDb,
		SessionDB: &sessionDb,
	}

	http.HandleFunc("/api/rvt/create", rvtApiHandler.Generate)
	http.HandleFunc("/api/rvt/list", rvtApiHandler.List)
	http.HandleFunc("/api/rvt/execute", rvtApiHandler.Execute)

	http.HandleFunc("/api/user/register", userApiHandler.Register)
	http.HandleFunc("/api/user/login", userApiHandler.Login)
	http.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)
	http.HandleFunc("/api/user/logout", userApiHandler.Logout)

	// http.Handle("/", http.FileServer(http.Dir("./_static")))
	http.HandleFunc("/", ProxyDevUI)
}
