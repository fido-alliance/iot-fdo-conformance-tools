package externalapi

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func ProxyDevUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	urlInst, _ := url.Parse("http://localhost:5173")

	proxy := httputil.NewSingleHostReverseProxy(urlInst)

	r.URL.Host = urlInst.Host
	r.URL.Scheme = urlInst.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = urlInst.Host

	proxy.ServeHTTP(w, r)
}
