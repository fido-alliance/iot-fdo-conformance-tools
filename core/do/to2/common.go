package to2

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/dgraph-io/badger/v4"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/do/dbs"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	tdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	listenertestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/listener"
)

const MAX_NUM_OVENTRIES = 255
const agreedWaitSeconds uint32 = 30 * 24 * 60 * 60 // 1 month

type DoTo2 struct {
	session    *dbs.SessionDB
	voucher    *dbs.VoucherDB
	listenerDB *tdbs.ListenerTestDB
	ctx        context.Context
}

func NewDoTo2(db *badger.DB, ctx context.Context) DoTo2 {
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

func (h *DoTo2) receiveAndVerify(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (*dbs.SessionEntry, []byte, string, []byte, *listenertestsdeps.RequestListenerInst, error) {
	if !fdoshared.CheckHeaders(w, r, fdoshared.TO2_64_PROVE_DEVICE) {
		return nil, []byte{}, "", []byte{}, nil, fmt.Errorf("Error checking header!")
	}

	headerIsOk, sessionId, authorizationHeader := fdoshared.ExtractAuthorizationHeader(w, r, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY)
	if !headerIsOk {
		return nil, []byte{}, "", []byte{}, nil, fmt.Errorf("Error getting session header!")
	}

	session, err := h.session.GetSessionEntry(sessionId)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("%d: Can not find session... %s", currentCmd, err.Error()), http.StatusUnauthorized, nil, fdoshared.To2)
		return nil, []byte{}, "", []byte{}, nil, fmt.Errorf("%d: Can not find session... %s", currentCmd, err.Error())
	}

	// Conformance
	testcomListener, err := h.listenerDB.GetEntryByFdoGuid(session.Guid)
	if err != nil {
		log.Println("NO TEST CASE FOR %s. %s ", hex.EncodeToString(session.Guid[:]), err.Error())
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "Failed to read body!", http.StatusBadRequest, testcomListener, fdoshared.To2)

		return nil, []byte{}, "", []byte{}, testcomListener, fmt.Errorf("%d: Error reading body... %s", currentCmd, err.Error())
	}
	return session, sessionId, authorizationHeader, bodyBytes, testcomListener, nil
}

func (h *DoTo2) receiveAndDecrypt(w http.ResponseWriter, r *http.Request, currentCmd fdoshared.FdoCmd) (*dbs.SessionEntry, []byte, string, []byte, *listenertestsdeps.RequestListenerInst, error) {
	session, sessionId, authorizationHeader, rawBodyBytes, testcomListener, err := h.receiveAndVerify(w, r, currentCmd)
	if err != nil {
		return nil, []byte{}, "", []byte{}, testcomListener, err
	}

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawBodyBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("%d: Error decrypting... %s", currentCmd, err.Error()), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return nil, []byte{}, "", []byte{}, testcomListener, fmt.Errorf("%d: Error decrypting... %s", currentCmd, err.Error())
	}

	return session, sessionId, authorizationHeader, bodyBytes, testcomListener, nil
}
