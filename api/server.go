package api

import (
	"context"
	"net/http"

	"github.com/dgraph-io/badger/v4"
	"github.com/gorilla/mux"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api/testapi"
	dodbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	testdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"
)

func AddContext(next http.Handler, ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SetupServer(db *badger.DB, ctx context.Context) {
	userDb := dbs.NewUserTestDB(db)
	rvtDb := testdbs.NewRequestTestDB(db)
	sessionDb := dbs.NewSessionDB(db)
	configDb := dbs.NewConfigDB(db)
	devBaseDb := dbs.NewDeviceBaseDB(db)
	listenerDb := testdbs.NewListenerTestDB(db)
	doVoucherDb := dodbs.NewVoucherDB(db)

	rvtApiHandler := testapi.RVTestMgmtAPI{
		UserDB:    userDb,
		ReqTDB:    rvtDb,
		SessionDB: sessionDb,
		ConfigDB:  configDb,
		DevBaseDB: devBaseDb,
		Ctx:       ctx,
	}

	dotApiHandler := testapi.DOTestMgmtAPI{
		UserDB:    userDb,
		ReqTDB:    rvtDb,
		SessionDB: sessionDb,
		ConfigDB:  configDb,
		DevBaseDB: devBaseDb,
	}

	deviceApiHandler := testapi.DeviceTestMgmtAPI{
		UserDB:       userDb,
		ListenerDB:   listenerDb,
		SessionDB:    sessionDb,
		ConfigDB:     configDb,
		DevBaseDB:    devBaseDb,
		DOVouchersDB: doVoucherDb,
		Ctx:          ctx,
	}

	userApiHandler := UserAPI{
		UserDB:    userDb,
		SessionDB: sessionDb,
	}

	iopApi := IopApi{
		DOVouchersDB: doVoucherDb,
		Ctx:          ctx,
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

	r.HandleFunc("/api/iop/do/add", iopApi.IopAddVoucherToDO)
	r.HandleFunc("/api/iop/is_iop_only", iopApi.IsOipOnly)

	r.HandleFunc("/api/user/login/onprem", userApiHandler.OnPremNoLogin)
	r.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)
	r.HandleFunc("/api/user/logout", userApiHandler.Logout)
	r.HandleFunc("/api/user/purgetests", userApiHandler.PurgeTests)

	if ctx.Value(fdoshared.CFG_DEV_ENV) == fdoshared.CFG_ENV_DEV {
		r.PathPrefix("/").HandlerFunc(ProxyDevUI)
	} else {
		r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/")))
	}

	http.Handle("/", AddContext(r, ctx))
}
