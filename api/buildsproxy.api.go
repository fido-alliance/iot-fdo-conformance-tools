package api

import (
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/fido-alliance/fdo-fido-conformance-server/api/commonapi"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/fido-alliance/fdo-shared"
)

type BuildsProxyAPI struct {
	UserDB    *dbs.UserTestDB
	SessionDB *dbs.SessionDB
}

func (h *BuildsProxyAPI) checkAutzAndGetUser(r *http.Request) (*dbs.UserTestDBEntry, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, errors.New("Failed to read cookie. " + err.Error())

	}

	if sessionCookie == nil {
		return nil, errors.New("Cookie does not exists")
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return nil, errors.New("Session expired. " + err.Error())
	}

	if !sessionInst.LoggedIn {
		return nil, errors.New("User is not logged in!" + err.Error())
	}

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *BuildsProxyAPI) ProxyBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_ENV_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		commonapi.RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	_, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	buildsApiUrl := r.Context().Value(fdoshared.CFG_ENV_API_BUILDS_URL)

	if buildsApiUrl == nil {
		commonapi.RespondError(w, "Server is down. ", http.StatusInternalServerError)
		return
	}

	urlInst, _ := url.Parse(buildsApiUrl.(string))

	proxy := httputil.NewSingleHostReverseProxy(urlInst)

	newPath := strings.Replace(r.URL.Path, "/api/builds/", "", 1)

	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}

	r.URL.Host = urlInst.Host
	r.URL.Scheme = urlInst.Scheme
	r.Host = urlInst.Host
	r.URL.Path = newPath

	proxy.ServeHTTP(w, r)
}
