package fdoshared

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

var (
	IOPLOGGER_SIM_ACTIVE SIM_ID = "fido_alliance:active"
	IOPLOGGER_SIM        SIM_ID = "fido_alliance:dev_conformance"
	IOPLOGGER_SIM_NAME   SIM_ID = "fido_alliance"
)

var IOPLOGGER_LOGGER_PATH = "/logger/101/msg"

type IopComp string

const (
	IopDO     IopComp = "DO"
	IopRV     IopComp = "RV"
	IopDEVICE IopComp = "DEVICE"
)

type IopLoggerPayload struct {
	_          struct{} `cbor:",toarray"`
	Guid       FdoGuid
	TOProtocol FdoToProtocol
	Nonce      FdoNonce
}

func SubmitIopLoggerEvent(ctx context.Context, guid FdoGuid, toProtocol FdoToProtocol, nonce FdoNonce, authzHeader string) error {
	if !ctx.Value(CFG_ENV_INTEROP_ENABLED).(bool) {
		return nil
	}

	payload := IopLoggerPayload{
		Guid:       guid,
		TOProtocol: toProtocol,
		Nonce:      nonce,
	}
	payloadBytes, _ := CborCust.Marshal(payload)

	srvUrl, err := url.JoinPath(ctx.Value(CFG_ENV_INTEROP_DASHBOARD_URL).(string), IOPLOGGER_LOGGER_PATH)
	if err != nil {
		return fmt.Errorf("error joining IOP logger URL path: %s", err.Error())
	}

	fmt.Println("Submitting IOP logger event to", srvUrl)

	req, err := http.NewRequest("POST", srvUrl, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return errors.New("Error creating new request. " + err.Error())
	}

	req.Header.Set("Authorization", authzHeader)
	req.Header.Set("Content-Type", "application/cbor")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("Error sending post request to %s url. %s", srvUrl, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading body bytes for %s url. %s", srvUrl, err.Error())
	}

	if resp.StatusCode != 200 {
		fdoErrInst, err := DecodeErrorResponse(bodyBytes)
		if err != nil {
			return fmt.Errorf("error submitting IOP logger event. HTTP status code: %d", resp.StatusCode)
		}

		return fmt.Errorf("error submitting IOP logger event. FDO status code: %s", fdoErrInst.EMErrorStr)
	}

	log.Println("IOP logger event submitted successfully")
	return nil
}

func IopGetAuthz(ctx context.Context, comp IopComp) (string, error) {
	switch comp {
	case IopDO:
		return ctx.Value(CFG_ENV_INTEROP_DASHBOARD_DO_AUTHZ).(string), nil
	case IopRV:
		return ctx.Value(CFG_ENV_INTEROP_DASHBOARD_RV_AUTHZ).(string), nil
	}

	return "", fmt.Errorf("invalid component %s", comp)
}
