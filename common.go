package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/WebauthnWorks/fdo-rv/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

func RespondFDOError(w http.ResponseWriter, r *http.Request, errorCode fdoshared.FdoErrorCode, prevMsgId fdoshared.FdoCmd, messageStr string, httpStatusCode int) {
	fdoErrorInst := fdoshared.NewFdoError(errorCode, prevMsgId, messageStr)

	// fmt.Printf() // TODO

	fdoErrorBytes, _ := cbor.Marshal(fdoErrorInst)

	w.Header().Add("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Add("Message-Type", fdoshared.TO_ERROR_255.ToString())
	w.WriteHeader(httpStatusCode)
	w.Write(fdoErrorBytes)
}

func ExtractAuthorizationHeader(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (bool, []byte, string) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Missing authorization header!", http.StatusUnauthorized)
		return false, nil, ""
	}

	authorizationHeaderParts := strings.Split(authorizationHeader, " ")
	if len(authorizationHeaderParts) != 2 {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Invalid authorization header!", http.StatusUnauthorized)
		return false, nil, ""
	}

	if authorizationHeaderParts[0] != "Bearer" {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Authorization token is not of type bearer!", http.StatusUnauthorized)
		return false, nil, ""
	}

	return true, []byte(authorizationHeaderParts[1]), authorizationHeader
}

func CheckHeaders(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) bool {
	if r.Method != "POST" {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Method not allowed!", http.StatusMethodNotAllowed)
		return false
	}

	receivedContentType := r.Header.Get("Content-Type")
	if receivedContentType != fdoshared.CONTENT_TYPE_CBOR {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected application type \"%s\". Received \"%s\".", fdoshared.CONTENT_TYPE_CBOR, receivedContentType), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}
