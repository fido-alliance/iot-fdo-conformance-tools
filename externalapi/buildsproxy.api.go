package externalapi

import (
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
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

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *BuildsProxyAPI) ProxyBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	if r.Context().Value(fdoshared.CFG_MODE) == fdoshared.CFG_MODE_ONPREM {
		log.Println("Only allowed for on-line build!")
		RespondError(w, "Unauthorized!", http.StatusUnauthorized)
		return
	}

	_, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	urlInst, _ := url.Parse("https://fidotools:5E5GL3S6PaqL7ll5HgvG@builds.fidoalliance.org")

	proxy := httputil.NewSingleHostReverseProxy(urlInst)

	newPath := strings.Replace(r.URL.Path, "/api/builds/", "", 1)

	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}

	r.URL.Host = urlInst.Host
	r.URL.Scheme = urlInst.Scheme
	r.Host = urlInst.Host
	r.URL.Path = newPath

	log.Println(r.URL.Path)
	proxy.ServeHTTP(w, r)
}
