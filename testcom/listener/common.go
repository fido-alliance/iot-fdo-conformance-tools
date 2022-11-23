package listener

import (
	"net/http"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func Conf_RespondFDOError(w http.ResponseWriter, r *http.Request, errorCode fdoshared.FdoErrorCode, prevMsgId fdoshared.FdoCmd, messageStr string, httpStatusCode int, testcomListener *RequestListenerInst, fdoProtocol fdoshared.FdoToProtocol) {
	if testcomListener != nil {
		switch fdoProtocol {
		case fdoshared.To0:
			testcomListener.To0.PushFail(messageStr)
		case fdoshared.To1:
			testcomListener.To1.PushFail(messageStr)
		case fdoshared.To2:
			testcomListener.To2.PushFail(messageStr)
		}
	}

	fdoshared.RespondFDOError(w, r, errorCode, prevMsgId, messageStr, httpStatusCode)
}
