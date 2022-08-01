package to2

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

const MAX_NUM_OVENTRIES = 255
const agreedWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type DoTo2 struct {
	Session *dbs.SessionDB
	Voucher *dbs.VoucherDB
}

func ValidateDeviceSIMs(guid fdoshared.FdoGuid, sims []fdoshared.ServiceInfoKV) error {
	for _, module := range sims {
		// TODO
		log.Println(module.ServiceInfoKey)
	}

	return nil
}

func GetOwnerSIMs(guid fdoshared.FdoGuid) ([]fdoshared.ServiceInfoKV, error) {

	return []fdoshared.ServiceInfoKV{}, nil
}

func (h *DoTo2) receiveAndDecrypt(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (*dbs.SessionEntry, []byte, string, []byte, error) {
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO2_64_PROVE_DEVICE) {
		return nil, []byte{}, "", []byte{}, fmt.Errorf("Error checking header!")
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY)
	if !headerIsOk {
		return nil, []byte{}, "", []byte{}, fmt.Errorf("Error getting session header!")
	}

	session, err := h.Session.GetSessionEntry(sessionId)
	if err != nil {
		log.Printf("%d: Can not find session... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Unauthorized", http.StatusUnauthorized)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Can not find session... %s", currentCmd, err.Error())
	}

	rawBodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("%d: Error reading body... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Failed to read body!", http.StatusBadRequest)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Error reading body... %s", currentCmd, err.Error())
	}

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawBodyBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Printf("%d: Error decrypting... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Internal server error!", http.StatusInternalServerError)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Error decrypting... %s", currentCmd, err.Error())
	}

	return session, sessionId, authorizationHeader, bodyBytes, nil
}
