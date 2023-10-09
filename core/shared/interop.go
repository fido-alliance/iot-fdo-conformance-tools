package fdoshared

import (
	"context"
	"fmt"
)

var IOPLOGGER_SIM SIM_ID = "fido_alliance:dev_conformance"
var IOPLOGGER_LOGGER_PATH = "/logger/101/msg/"

var IOPLOGGER_LOGGER_CMD FdoCmd = 10

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

	var payload = IopLoggerPayload{
		Guid:       guid,
		TOProtocol: toProtocol,
		Nonce:      nonce,
	}
	payloadBytes, _ := CborCust.Marshal(payload)

	srvUrl := ctx.Value(CFG_ENV_INTEROP_DASHBOARD_URL).(string) + IOPLOGGER_LOGGER_PATH

	bodyBytes, _, httpStatusCode, err := SendCborPost(
		SRVEntry{SrvURL: srvUrl, OverrideURL: true},
		IOPLOGGER_LOGGER_CMD, payloadBytes, &authzHeader,
	)
	if err != nil {
		return fmt.Errorf("error submitting IOP logger event. %s", err.Error())
	}

	if httpStatusCode != 200 {
		fdoErrInst, err := DecodeErrorResponse(bodyBytes)
		if err != nil {
			return fmt.Errorf("error submitting IOP logger event. HTTP status code: %d", httpStatusCode)
		}

		return fmt.Errorf("error submitting IOP logger event. FDO status code: %s", fdoErrInst.EMErrorStr)
	}

	return nil
}

func IopGetAuthz(ctx context.Context, comp IopComp) (string, error) {
	switch comp {
	case IopDO:
		return ctx.Value(CFG_ENV_INTEROP_DASHBOARD_RV_AUTHZ).(string), nil
	case IopRV:
		return ctx.Value(CFG_ENV_INTEROP_DASHBOARD_DO_AUTHZ).(string), nil
	case IopDEVICE:
		return ctx.Value(CFG_ENV_INTEROP_DASHBOARD_DEVICE_AUTHZ).(string), nil
	}

	return "", fmt.Errorf("invalid component %s", comp)
}
