package externalapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	fdodocommon "github.com/WebauthnWorks/fdo-device-implementation/common"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	testcomdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"
	listenertestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/listener"

	"github.com/gorilla/mux"
)

type DeviceTestMgmtAPI struct {
	UserDB     *dbs.UserTestDB
	ListenerDB *testcomdbs.ListenerTestDB
	DevBaseDB  *dbs.DeviceBaseDB
	SessionDB  *dbs.SessionDB
	ConfigDB   *dbs.ConfigDB
}

func (h *DeviceTestMgmtAPI) checkAutzAndGetUser(r *http.Request) (*dbs.UserTestDBEntry, error) {
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

	userInst, err := h.UserDB.Get(sessionInst.Username)
	if err != nil {
		return nil, errors.New("User does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *DeviceTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
	if !CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var createTestCase Device_CreateTestCase
	err = json.Unmarshal(bodyBytes, &createTestCase)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if len(createTestCase.Name) == 0 || len(createTestCase.VoucherAndPrivateKey) == 0 {
		log.Println("Missing name or voucher.")
		RespondError(w, "Missing name or voucher!", http.StatusBadRequest)
		return
	}

	newVand, err := fdodocommon.DecodePemVoucherAndKey(createTestCase.VoucherAndPrivateKey)
	if err != nil {
		log.Println("Failed to decode voucher. " + err.Error())
		RespondError(w, "Failed to decode voucher! "+err.Error(), http.StatusBadRequest)
		return
	}

	ovHeader, _ := newVand.Voucher.GetOVHeader()

	deviceListenerInsts := listenertestsdeps.NewDevice_RequestListenerInst(*newVand, ovHeader.OVGuid)
	err = h.ListenerDB.Save(deviceListenerInsts)
	if err != nil {
		log.Println("Failed to decode voucher. " + err.Error())
		RespondError(w, "Failed to decode voucher! "+err.Error(), http.StatusBadRequest)
		return
	}

	userInst.DeviceTestInsts = append(userInst.DeviceTestInsts, dbs.NewDeviceTestInst(createTestCase.Name, deviceListenerInsts.Uuid, ovHeader.OVGuid))

	err = h.UserDB.Save(userInst.Username, *userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	RespondSuccess(w)
}

func (h *DeviceTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	listDeviceRuns := Device_ListRuns{
		DeviceItems: []Device_Item{},
	}

	for _, devInsts := range userInst.DeviceTestInsts {
		reqListener, err := h.ListenerDB.Get(devInsts.ListenerUuid)
		if err != nil {
			log.Printf("Failed find entry for %s. %s", hex.EncodeToString(devInsts.Uuid), err.Error())
			continue
		}

		var to1testRunHistory []listenertestsdeps.ListenerTestRun = []listenertestsdeps.ListenerTestRun{}
		if reqListener.To1.Running {
			to1testRunHistory = append([]listenertestsdeps.ListenerTestRun{reqListener.To1.CurrentTestRun}, reqListener.To1.TestRunHistory...)
		} else {
			to1testRunHistory = reqListener.To1.TestRunHistory
		}

		var to2testRunHistory []listenertestsdeps.ListenerTestRun = []listenertestsdeps.ListenerTestRun{}
		if reqListener.To2.Running {
			to2testRunHistory = append([]listenertestsdeps.ListenerTestRun{reqListener.To2.CurrentTestRun}, reqListener.To2.TestRunHistory...)
		} else {
			to2testRunHistory = reqListener.To2.TestRunHistory
		}

		listDeviceRuns.DeviceItems = append(listDeviceRuns.DeviceItems, Device_Item{
			Id:   hex.EncodeToString(reqListener.Uuid),
			Name: fmt.Sprintf("%s GUID(%s)", devInsts.Name, hex.EncodeToString(devInsts.DeviceGuid[:])),
			To1:  to1testRunHistory,
			To2:  to2testRunHistory,
		})
	}

	listDeviceRuns.Status = FdoApiStatus_OK

	RespondSuccessStruct(w, listDeviceRuns)
}

func (h *DeviceTestMgmtAPI) StartNewTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)

	toprotocol := vars["toprotocol"]
	testinsthex := vars["testinsthex"]

	if len(testinsthex) == 0 {
		RespondError(w, "Missing testInstID or testRunID!", http.StatusBadRequest)
		return
	}

	testIstIdBytes, err := hex.DecodeString(testinsthex)
	if err != nil {
		RespondError(w, "Failed to decode test inst id!", http.StatusBadRequest)
		return
	}

	if !userInst.DeviceT_ContainID(testIstIdBytes) {
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	topInt, err := strconv.ParseInt(toprotocol, 10, 64)
	if err != nil {
		RespondError(w, "Failed to decode TO Protocol ID!", http.StatusBadRequest)
		return
	}

	reqListInst, err := h.ListenerDB.Get(testIstIdBytes)
	if err != nil {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	runnerInst, err := reqListInst.GetProtocolInst(int(topInt))
	if err != nil {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	runnerInst.StartNewTestRun()

	err = h.ListenerDB.Update(*reqListInst)
	if err != nil {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	RespondSuccess(w)
}

func (h *DeviceTestMgmtAPI) DeleteTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)

	toprotocol := vars["toprotocol"]
	testinsthex := vars["testinsthex"]
	testrunid := vars["testrunid"]

	if len(testinsthex) == 0 || len(testrunid) == 0 {
		RespondError(w, "Missing testInstID or testRunID!", http.StatusBadRequest)
		return
	}

	log.Println(testinsthex)
	testIstIdBytes, err := hex.DecodeString(testinsthex)
	if err != nil {
		RespondError(w, "Failed to decode test inst id!", http.StatusBadRequest)
		return
	}

	if !userInst.DeviceT_ContainID(testIstIdBytes) {
		RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	topInt, err := strconv.ParseInt(toprotocol, 10, 64)
	if err != nil {
		RespondError(w, "Failed to decode TO Protocol ID!", http.StatusBadRequest)
		return
	}

	h.ListenerDB.RemoveTestRun(fdoshared.FdoToProtocol(topInt), testIstIdBytes, testrunid)

	RespondSuccess(w)
}
