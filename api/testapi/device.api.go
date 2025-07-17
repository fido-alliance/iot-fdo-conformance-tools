package testapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api/commonapi"
	fdodocommon "github.com/fido-alliance/iot-fdo-conformance-tools/core/device/common"
	dodbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do/to0"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	testcomdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	listenertestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"
)

type DeviceTestMgmtAPI struct {
	UserDB       *dbs.UserTestDB
	ListenerDB   *testcomdbs.ListenerTestDB
	DevBaseDB    *dbs.DeviceBaseDB
	SessionDB    *dbs.SessionDB
	ConfigDB     *dbs.ConfigDB
	DOVouchersDB *dodbs.VoucherDB
	Ctx          context.Context
}

func (h *DeviceTestMgmtAPI) submitToRvOwnerSign(voucherdbe *fdoshared.VoucherDBEntry) error {
	to0client := to0.NewTo0Requestor(fdoshared.SRVEntry{
		SrvURL: h.Ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string),
	}, *voucherdbe, h.Ctx)

	helloAck21, _, err := to0client.Hello20(testcom.NULL_TEST)
	if err != nil {
		return fmt.Errorf("error submitting OwnerSign. %s", err.Error())
	}

	_, _, err = to0client.OwnerSign22(helloAck21.NonceTO0Sign, testcom.NULL_TEST)
	if err != nil {
		return fmt.Errorf("error submitting OwnerSign. %s", err.Error())
	}

	return nil
}

func (h *DeviceTestMgmtAPI) submitVoucherToDO(voucherDBEntry *fdoshared.VoucherDBEntry) error {
	return h.DOVouchersDB.Save(*voucherDBEntry)
}

func (h *DeviceTestMgmtAPI) checkAutzAndGetUser(r *http.Request) (*dbs.UserTestDBEntry, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, errors.New("failed to read cookie. " + err.Error())
	}

	if sessionCookie == nil {
		return nil, errors.New("cookie does not exists")
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return nil, errors.New("session expired. " + err.Error())
	}

	if !sessionInst.LoggedIn {
		return nil, errors.New("unauthorized")
	}

	userInst, err := h.UserDB.Get(sessionInst.Email)
	if err != nil {
		return nil, errors.New("user does not exists. " + err.Error())
	}

	return userInst, nil
}

func (h *DeviceTestMgmtAPI) Generate(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var createTestCase Device_CreateTestCase
	err = json.Unmarshal(bodyBytes, &createTestCase)
	if err != nil {
		log.Println("Failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if len(createTestCase.Name) == 0 || len(createTestCase.VoucherAndPrivateKey) == 0 {
		log.Println("Missing name or voucher.")
		commonapi.RespondError(w, "Missing name or voucher!", http.StatusBadRequest)
		return
	}

	newVand, err := fdodocommon.DecodePemVoucherAndKey(createTestCase.VoucherAndPrivateKey)
	if err != nil {
		log.Println("Failed to decode voucher. " + err.Error())
		commonapi.RespondError(w, "Failed to decode voucher! "+err.Error(), http.StatusBadRequest)
		return
	}

	err = h.submitToRvOwnerSign(newVand)
	if err != nil {
		log.Println("Failed submit owner sign to RV! " + err.Error())
		commonapi.RespondError(w, "Failed submit owner sign to RV! "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.submitVoucherToDO(newVand)
	if err != nil {
		log.Println("Error submitting voucher to DO " + err.Error())
		commonapi.RespondError(w, "Error submitting voucher to DO! "+err.Error(), http.StatusInternalServerError)
		return
	}

	ovHeader, _ := newVand.Voucher.GetOVHeader()

	deviceListenerInsts := listenertestsdeps.NewDevice_RequestListenerInst(*newVand, ovHeader.OVGuid)
	err = h.ListenerDB.Save(deviceListenerInsts)
	if err != nil {
		log.Println("Failed to decode voucher. " + err.Error())
		commonapi.RespondError(w, "Failed to decode voucher! "+err.Error(), http.StatusBadRequest)
		return
	}

	userInst.DeviceTestInsts = append(userInst.DeviceTestInsts, dbs.NewDeviceTestInst(createTestCase.Name, deviceListenerInsts.Uuid, ovHeader.OVGuid))

	err = h.UserDB.Save(*userInst)
	if err != nil {
		log.Println("Failed to save user. " + err.Error())
		commonapi.RespondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *DeviceTestMgmtAPI) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
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
			Name: devInsts.Name,
			Guid: hex.EncodeToString(devInsts.DeviceGuid[:]),
			To1:  to1testRunHistory,
			To2:  to2testRunHistory,
		})
	}

	listDeviceRuns.Status = commonapi.FdoApiStatus_OK

	commonapi.RespondSuccessStruct(w, listDeviceRuns)
}

func (h *DeviceTestMgmtAPI) StartNewTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Request params
	vars := mux.Vars(r)
	toprotocol := vars["toprotocol"]
	testinsthex := vars["testinsthex"]

	if len(testinsthex) == 0 {
		commonapi.RespondError(w, "Missing testInstID or testRunID!", http.StatusBadRequest)
		return
	}

	testInstIdBytes, err := hex.DecodeString(testinsthex)
	if err != nil {
		commonapi.RespondError(w, "Failed to decode test inst id!", http.StatusBadRequest)
		return
	}

	if !userInst.DeviceT_ContainID(testInstIdBytes) {
		commonapi.RespondError(w, "Invalid test id!", http.StatusBadRequest)
		return
	}

	toPInt, err := strconv.ParseInt(toprotocol, 10, 64)
	if err != nil {
		commonapi.RespondError(w, "Failed to decode TO Protocol ID!", http.StatusBadRequest)
		return
	}

	reqListInst, err := h.ListenerDB.Get(testInstIdBytes)
	if err != nil {
		commonapi.RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	runnerInst, err := reqListInst.GetProtocolInst(int(toPInt))
	if err != nil {
		commonapi.RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	runnerInst.StartNewTestRun()

	err = h.ListenerDB.Update(reqListInst)
	if err != nil {
		commonapi.RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	commonapi.RespondSuccess(w)
}

func (h *DeviceTestMgmtAPI) DeleteTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		commonapi.RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	userInst, err := h.checkAutzAndGetUser(r)
	if err != nil {
		log.Println("Failed to read cookie. " + err.Error())
		commonapi.RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)

	toprotocol := vars["toprotocol"]
	testinsthex := vars["testinsthex"]
	testrunid := vars["testrunid"]

	if len(testinsthex) == 0 || len(testrunid) == 0 {
		commonapi.RespondError(w, "Missing testInstID or testRunID!", http.StatusBadRequest)
		return
	}

	log.Println(testinsthex)
	testIstIdBytes, err := hex.DecodeString(testinsthex)
	if err != nil {
		commonapi.RespondError(w, "Failed to decode test inst id!", http.StatusBadRequest)
		return
	}

	if !userInst.DeviceT_ContainID(testIstIdBytes) {
		commonapi.RespondError(w, "Invalid id!", http.StatusBadRequest)
		return
	}

	topInt, err := strconv.ParseInt(toprotocol, 10, 64)
	if err != nil {
		commonapi.RespondError(w, "Failed to decode TO Protocol ID!", http.StatusBadRequest)
		return
	}

	h.ListenerDB.RemoveTestRun(fdoshared.FdoToProtocol(topInt), testIstIdBytes, testrunid)

	commonapi.RespondSuccess(w)
}
