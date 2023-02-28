package api

import (
	"context"
	"net/http"

	dodbs "github.com/fido-alliance/fdo-do/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/api/testapi"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/services"
	"github.com/fido-alliance/fdo-fido-conformance-server/tools"
	testdbs "github.com/fido-alliance/fdo-shared/testcom/dbs"

	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
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
	verifyDb := dbs.NewVerifyDB(db)

	notifyService := services.NewNotifyService(
		ctx.Value(tools.CFG_ENV_NOTIFY_SERVICE_HOST).(string),
		ctx.Value(tools.CFG_ENV_NOTIFY_SERVICE_SECRET).(string),
		verifyDb)

	rvtApiHandler := testapi.RVTestMgmtAPI{
		UserDB:    userDb,
		ReqTDB:    rvtDb,
		SessionDB: sessionDb,
		ConfigDB:  configDb,
		DevBaseDB: devBaseDb,
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
	}

	userApiHandler := UserAPI{
		UserDB:    userDb,
		SessionDB: sessionDb,
		Notify:    &notifyService,
	}

	userVerifyHandler := UserVerify{
		UserDB:        userDb,
		VerifyDB:      verifyDb,
		SessionDB:     sessionDb,
		NotifyService: &notifyService,
	}

	buildsProxyHandler := BuildsProxyAPI{
		UserDB:    userDb,
		SessionDB: sessionDb,
	}

	adminApi := AdminApi{
		UserDB:        userDb,
		VerifyDB:      verifyDb,
		NotifyService: &notifyService,
	}

	oauth2ApiHandle := OAuth2API{
		UserDB:    userDb,
		SessionDB: sessionDb,
		Notify:    notifyService,
		OAuth2Service: &services.OAuth2Service{
			Providers: map[services.OAuth2ProviderID]services.OAuth2Provider{
				services.OATH2_GITHUB: services.NewGithubOAuth2Connector(services.OAuth2ProviderConfig{
					ClientId:     ctx.Value(tools.CFG_ENV_GITHUB_CLIENTID).(string),
					ClientSecret: ctx.Value(tools.CFG_ENV_GITHUB_CLIENTSECRET).(string),
					RedirectUrl:  ctx.Value(tools.CFG_ENV_GITHUB_REDIRECTURL).(string),
				}),
				services.OATH2_GOOGLE: services.NewGoogleOAuth2Connector(services.OAuth2ProviderConfig{
					ClientId:     ctx.Value(tools.CFG_ENV_GOOGLE_CLIENTID).(string),
					ClientSecret: ctx.Value(tools.CFG_ENV_GOOGLE_CLIENTSECRET).(string),
					RedirectUrl:  ctx.Value(tools.CFG_ENV_GOOGLE_REDIRECTURL).(string),
				}),
			},
		},
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

	r.PathPrefix("/api/builds/").HandlerFunc(buildsProxyHandler.ProxyBuilds)

	r.HandleFunc("/api/user/register", userApiHandler.Register)
	r.HandleFunc("/api/user/register/additionalinfo", userApiHandler.AdditionalInfo)
	r.HandleFunc("/api/user/login", userApiHandler.Login)
	r.HandleFunc("/api/user/login/onprem", userApiHandler.OnPremNoLogin)
	r.HandleFunc("/api/user/loggedin", userApiHandler.UserLoggedIn)
	r.HandleFunc("/api/user/email/resendverification", userApiHandler.ReRequestEmailValidationLink)
	r.HandleFunc("/api/user/logout", userApiHandler.Logout)
	r.HandleFunc("/api/user/purgetests", userApiHandler.PurgeTests)
	r.HandleFunc("/api/user/config", userApiHandler.Config)

	r.HandleFunc("/api/user/approve/{id}/{email}", userVerifyHandler.Check)
	r.HandleFunc("/api/user/reject/{id}/{email}", userVerifyHandler.Reject)
	r.HandleFunc("/api/user/email/check/{id}/{email}", userVerifyHandler.Check)

	r.HandleFunc("/api/user/password/reset/init", userVerifyHandler.PasswordResetInit)
	r.HandleFunc("/api/user/password/reset/{id}/{email}", userVerifyHandler.PasswordResetCheck)
	r.HandleFunc("/api/user/password/reset", userVerifyHandler.PasswordResetSet)

	r.HandleFunc("/api/oauth2/{providerid}/init", oauth2ApiHandle.InitWithRedirectUrl)
	r.HandleFunc("/api/oauth2/{providerid}/callback", oauth2ApiHandle.ProcessCallback)

	r.HandleFunc("/api/admin/users", adminApi.GetUserList)
	r.HandleFunc("/api/admin/users/{action}/{email}", adminApi.SetUserAccountState)

	if ctx.Value(tools.CFG_DEV_ENV) == tools.ENV_DEV {
		r.PathPrefix("/").HandlerFunc(ProxyDevUI)
	} else {
		r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/")))
	}

	http.Handle("/", AddContext(r, ctx))
}
