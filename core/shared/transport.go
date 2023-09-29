package fdoshared

import (
	"fmt"
	"net/http"
	"strings"
)

const CONTENT_TYPE_CBOR string = "application/cbor"
const FDO_101_URL_BASE string = "/fdo/101/msg/"

func RespondFDOError(w http.ResponseWriter, r *http.Request, errorCode FdoErrorCode, prevMsgId FdoCmd, messageStr string, httpStatusCode int) {
	fdoErrorInst := NewFdoError(errorCode, prevMsgId, messageStr)

	fdoErrorBytes, _ := CborCust.Marshal(fdoErrorInst)

	w.Header().Add("Content-Type", CONTENT_TYPE_CBOR)
	w.Header().Add("Message-Type", TO_ERROR_255.ToString())
	w.WriteHeader(httpStatusCode)
	w.Write(fdoErrorBytes)
}

func ExtractAuthorizationHeader(w http.ResponseWriter, r *http.Request, currentCmd FdoCmd) (bool, []byte, string) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		RespondFDOError(w, r, MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Missing authorization header!", http.StatusUnauthorized)
		return false, nil, ""
	}

	authorizationHeaderParts := strings.Split(authorizationHeader, " ")
	if len(authorizationHeaderParts) != 2 {
		RespondFDOError(w, r, MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Invalid authorization header!", http.StatusUnauthorized)
		return false, nil, ""
	}

	if authorizationHeaderParts[0] != "Bearer" {
		RespondFDOError(w, r, MESSAGE_BODY_ERROR, currentCmd, "Unauthorized! Authorization token is not of type bearer!", http.StatusUnauthorized)
		return false, nil, ""
	}

	return true, []byte(authorizationHeaderParts[1]), authorizationHeader
}

func CheckHeaders(w http.ResponseWriter, r *http.Request, currentCmd FdoCmd) bool {
	if r.Method != "POST" {
		RespondFDOError(w, r, MESSAGE_BODY_ERROR, currentCmd, "Method not allowed!", http.StatusMethodNotAllowed)
		return false
	}

	receivedContentType := r.Header.Get("Content-Type")
	if receivedContentType != CONTENT_TYPE_CBOR {
		RespondFDOError(w, r, MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected application type \"%s\". Received \"%s\".", CONTENT_TYPE_CBOR, receivedContentType), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}
