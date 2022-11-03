package to2

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/WebauthnWorks/fdo-do/dbs"
	tdbs "github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
)

const MAX_NUM_OVENTRIES = 255
const agreedWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type DoTo2 struct {
	session    *dbs.SessionDB
	voucher    *dbs.VoucherDB
	listenerDB *tdbs.ListenerTestDB
}

func NewDoTo2(db *badger.DB) DoTo2 {
	newListenerDb := tdbs.NewListenerTestDB(db)
	sessionDb := dbs.NewSessionDB(db)
	voucherDb := dbs.NewVoucherDB(db)
	return DoTo2{
		session:    sessionDb,
		voucher:    voucherDb,
		listenerDB: newListenerDb,
	}
}

func ValidateDeviceSIMs(guid fdoshared.FdoGuid, sims []fdoshared.ServiceInfoKV) error {
	for _, module := range sims {
		// TODO
		log.Println(module.ServiceInfoKey)
	}

	return nil
}

func GetOwnerSIMs(guid fdoshared.FdoGuid) ([]fdoshared.ServiceInfoKV, error) {

	// TODO
	return []fdoshared.ServiceInfoKV{
		{
			ServiceInfoKey: "owner:test1",
			ServiceInfoVal: []byte("1234"),
		},
		{
			ServiceInfoKey: "owner:test2",
			ServiceInfoVal: []byte("1234"),
		},
		{
			ServiceInfoKey: "owner:test3",
			ServiceInfoVal: []byte("1234"),
		},
		{
			ServiceInfoKey: "owner:test4",
			ServiceInfoVal: []byte("1234"),
		},
		{
			ServiceInfoKey: "owner:test5",
			ServiceInfoVal: []byte("1234"),
		},
		{
			ServiceInfoKey: "owner:test6",
			ServiceInfoVal: []byte("1234"),
		},
	}, nil
}

func (h *DoTo2) receiveAndVerify(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (*dbs.SessionEntry, []byte, string, []byte, error) {
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO2_64_PROVE_DEVICE) {
		return nil, []byte{}, "", []byte{}, fmt.Errorf("Error checking header!")
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY)
	if !headerIsOk {
		return nil, []byte{}, "", []byte{}, fmt.Errorf("Error getting session header!")
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		log.Printf("%d: Can not find session... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Unauthorized", http.StatusUnauthorized)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Can not find session... %s", currentCmd, err.Error())
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("%d: Error reading body... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Failed to read body!", http.StatusBadRequest)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Error reading body... %s", currentCmd, err.Error())
	}
	return session, sessionId, authorizationHeader, bodyBytes, nil
}

func (h *DoTo2) receiveAndDecrypt(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (*dbs.SessionEntry, []byte, string, []byte, error) {
	session, sessionId, authorizationHeader, rawBodyBytes, err := h.receiveAndVerify(w, r, currentCmd)
	if err != nil {
		return nil, []byte{}, "", []byte{}, err
	}

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawBodyBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Printf("%d: Error decrypting... %s", currentCmd, err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, "Internal server error!", http.StatusInternalServerError)
		return nil, []byte{}, "", []byte{}, fmt.Errorf("%d: Error decrypting... %s", currentCmd, err.Error())
	}

	return session, sessionId, authorizationHeader, bodyBytes, nil
}
