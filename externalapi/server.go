package externalapi

import (
	"net/http"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	testdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"
	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
)

func SetupServer(db *badger.DB) {
	userDb := dbs.NewUserTestDB(db)
	rvtDb := testdbs.NewRequestTestDB(db)
	sessionDb := dbs.NewSessionDB(db)
	configDb := dbs.NewConfigDB(db)
	devBaseDb := dbs.NewDeviceBaseDB(db)
	listenerDb := testdbs.NewListenerTestDB(db)

	rvtApiHandler := RVTestMgmtAPI{
		UserDB:    userDb,
		ReqTDB:    rvtDb,
		SessionDB: sessionDb,
		ConfigDB:  configDb,
		DevBaseDB: devBaseDb,
	}

	dotApiHandler := DOTestMgmtAPI{
		UserDB:    userDb,
		ReqTDB:    rvtDb,
		SessionDB: sessionDb,
		ConfigDB:  configDb,
		DevBaseDB: devBaseDb,
	}

	deviceApiHandler := DeviceTestMgmtAPI{
		UserDB:     userDb,
		ListenerDB: listenerDb,
		SessionDB:  sessionDb,
		ConfigDB:   configDb,
		DevBaseDB:  devBaseDb,
	}

	userApiHandler := UserAPI{
		UserDB:    userDb,
		SessionDB: sessionDb,
	}

	r := mux.NewRouter()

	r.HandleFunc("/api/rvt/create", rvtApiHandler.Generate)
	r.HandleFunc("/api/rvt/testruns", rvtApiHandler.List)
	r.HandleFunc("/api/rvt/testruns/{testinsthex}/{testrunid}", rvtApiHandler.DeleteTestRun).Methods("DELETE")
	r.HandleFunc("/api/rvt/execute", rvtApiHandler.Execute)

	r.HandleFunc("/api/dot/create", dotApiHandler.Generate)
	r.HandleFunc("/api/dot/testruns", dotApiHandler.List)
	r.HandleFunc("/api/dot/testruns/{testinsthex}/{testrunid}", dotApiHandler.DeleteTestRun).Methods("DELETE")
	r.HandleFunc("/api/dot/vouchers/{uuid}", dotApiHandler.GetVouchers)
	r.HandleFunc("/api/dot/execute", dotApiHandler.Execute)

	r.HandleFunc("/api/device/create", deviceApiHandler.Generate)
	r.HandleFunc("/api/device/testruns", deviceApiHandler.List)
	r.HandleFunc("/api/device/testruns/{toprotocol}/{testinsthex}/{testrunid}", deviceApiHandler.DeleteTestRun).Methods("DELETE")
	r.HandleFunc("/api/device/testruns/{toprotocol}/{testinsthex}", deviceApiHandler.StartNewTestRun).Methods("POST")

	r.HandleFunc("/api/user/register", userApiHandler.Register)
	r.HandleFunc("/api/user/login", userApiHandler.Login)
	r.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)
	r.HandleFunc("/api/user/logout", userApiHandler.Logout)
	r.HandleFunc("/api/user/purgetests", userApiHandler.PurgeTests)

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/")))
	// r.PathPrefix("/").HandlerFunc(ProxyDevUI)

	http.Handle("/", r)

}
