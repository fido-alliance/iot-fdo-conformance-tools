package commonapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const CONTENT_TYPE_JSON string = "application/json"

func GenerateCookie(token []byte) *http.Cookie {
	expires := time.Now().Add(14 * 24 * time.Hour)
	cookie := http.Cookie{Name: "session", Value: string(token), Expires: expires, HttpOnly: true, Path: "/api/"}

	return &cookie
}

type FdoConfApiStatus string

const (
	FdoApiStatus_OK     FdoConfApiStatus = "ok"
	FdoApiStatus_Failed FdoConfApiStatus = "failed"
)

type FdoConformanceApiError struct {
	Status       FdoConfApiStatus `json:"status"`
	ErrorMessage string           `json:"errorMessage"`
}

func RespondError(w http.ResponseWriter, errorMessage string, httpErrorCode int) {
	log.Printf("Responding error: %s. HTTP code %d", errorMessage, httpErrorCode)
	errorResponse := FdoConformanceApiError{
		Status:       FdoApiStatus_Failed,
		ErrorMessage: errorMessage,
	}

	errorResponseBytes, _ := json.Marshal(errorResponse)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(httpErrorCode)
	w.Write(errorResponseBytes)
}

func RespondSuccess(w http.ResponseWriter) {
	errorResponse := FdoConformanceApiError{
		Status:       FdoApiStatus_OK,
		ErrorMessage: "",
	}

	errorResponseBytes, _ := json.Marshal(errorResponse)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write(errorResponseBytes)
}

func RespondSuccessStruct(w http.ResponseWriter, successStruct interface{}) {
	successStructBytes, _ := json.Marshal(successStruct)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write(successStructBytes)
}

func CheckHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return false
	}

	receivedContentType := r.Header.Get("Content-Type")
	if receivedContentType != CONTENT_TYPE_JSON {
		RespondError(w, "Unsupported media types!", http.StatusUnsupportedMediaType)
		return false
	}

	return true
}
