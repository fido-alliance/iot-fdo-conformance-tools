package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api/commonapi"
	fdodocommon "github.com/fido-alliance/iot-fdo-conformance-tools/core/device/common"
	dodbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do/to0"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

type Iop_AddVoucherToDoPayload struct {
	VoucherAndPrivateKey string `json:"voucher"`
}

type IopApiResponse struct {
	commonapi.FdoConformanceApiError
	Logs []string `json:"logs"`
}

type IopApi struct {
	DOVouchersDB *dodbs.VoucherDB
	Ctx          context.Context
}

func (h *IopApi) submitVoucherToRvs(voucherdbe *fdoshared.VoucherDBEntry) ([]string, error) {
	logStrings := []string{}

	ovHeader, err := voucherdbe.Voucher.GetOVHeader()
	if err != nil {
		return logStrings, fmt.Errorf("error getting OVHeader. %s", err.Error())
	}

	mappedRvInfo, err := fdoshared.GetMappedRVInfo(ovHeader.OVRvInfo)
	if err != nil {
		return logStrings, fmt.Errorf("error getting mapped RVInfo. %s", err.Error())
	}

	ownerMappedRvInfo := mappedRvInfo.GetOwnerOnly()

	for rvEntryIndex, mappedRvInfo := range ownerMappedRvInfo {
		for _, urlOption := range mappedRvInfo.GetOwnerUrls() {
			to0client := to0.NewTo0Requestor(fdoshared.SRVEntry{SrvURL: urlOption}, *voucherdbe, nil)

			helloAck21, _, err := to0client.Hello20(testcom.NULL_TEST)
			if err != nil {
				logStrings = append(logStrings, fmt.Sprintf("(%d)[%s]. error submitting Hello20. %s", rvEntryIndex, urlOption, err.Error()))
				continue
			}

			_, _, err = to0client.OwnerSign22(helloAck21.NonceTO0Sign, testcom.NULL_TEST)
			if err != nil {
				logStrings = append(logStrings, fmt.Sprintf("(%d)[%s]. error submitting OwnerSign22. %s", rvEntryIndex, urlOption, err.Error()))
				continue
			}

			break
		}
	}

	return logStrings, nil
}

func (h *IopApi) submitVoucherToDO(voucherDBEntry *fdoshared.VoucherDBEntry) error {
	return h.DOVouchersDB.Save(*voucherDBEntry)
}

func (h *IopApi) IopAddVoucherToDO(w http.ResponseWriter, r *http.Request) {
	if !commonapi.CheckHeaders(w, r) {
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("failed to read body. " + err.Error())
		commonapi.RespondError(w, "Failed to read body!", http.StatusBadRequest)
		return
	}

	var createTestCase Iop_AddVoucherToDoPayload
	err = json.Unmarshal(bodyBytes, &createTestCase)
	if err != nil {
		log.Println("failed to decode body. " + err.Error())
		commonapi.RespondError(w, "Failed to decode body!", http.StatusBadRequest)
		return
	}

	if len(createTestCase.VoucherAndPrivateKey) == 0 {
		log.Println("missing name or voucher.")
		commonapi.RespondError(w, "Missing name or voucher!", http.StatusBadRequest)
		return
	}

	newVand, err := fdodocommon.DecodePemVoucherAndKey(createTestCase.VoucherAndPrivateKey)
	if err != nil {
		log.Println("failed to decode voucher. " + err.Error())
		commonapi.RespondError(w, "Failed to decode voucher! "+err.Error(), http.StatusBadRequest)
		return
	}

	// Save voucher to DO DB
	err = h.submitVoucherToDO(newVand)
	if err != nil {
		log.Println("Error submitting voucher to DO " + err.Error())
		commonapi.RespondError(w, "Error submitting voucher to DO! "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save voucher to DO DB
	logStr, err := h.submitVoucherToRvs(newVand)
	if err != nil {
		log.Println("Error submitting voucher to RVs " + err.Error())
		commonapi.RespondError(w, "Error submitting voucher to RVs! "+err.Error(), http.StatusInternalServerError)
		return
	}

	commonapi.RespondSuccessStruct(w, IopApiResponse{
		FdoConformanceApiError: commonapi.FdoConformanceApiError{
			Status:       commonapi.FdoApiStatus_OK,
			ErrorMessage: "",
		},
		Logs: logStr,
	})
}

type IopIsOipOnlyResponse struct {
	OipOnly bool `json:"oipOnly"`
}

func (h *IopApi) IsOipOnly(w http.ResponseWriter, r *http.Request) {
	commonapi.RespondSuccessStruct(w, IopIsOipOnlyResponse{
		OipOnly: h.Ctx.Value(fdoshared.CFG_ENV_INTEROP_ENABLED).(bool),
	})
}
