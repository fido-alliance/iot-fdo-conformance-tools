package fdoshared

import (
	"context"
	"fmt"
)

var IOPLOGGER_SIM = "fido_alliance:dev_conformance"
var IOPLOGGER_LOGGER_PATH = "/logger/101/msg/"

var IOPLOGGER_LOGGER_CMD FdoCmd = 10

type IopLoggerPayload struct {
	_          struct{} `cbor:",toarray"`
	Guid       FdoGuid
	TOProtocol FdoToProtocol
	Nonce      FdoNonce
}

func SubmitIopLoggerEvent(ctx context.Context, guid FdoGuid, toProtocol FdoToProtocol, nonce FdoNonce, authzHeader string) error {
	var payload = IopLoggerPayload{
		Guid:       guid,
		TOProtocol: toProtocol,
		Nonce:      nonce,
	}

	payloadBytes, _ := CborCust.Marshal(payload)

	_, _, httpStatusCode, err := SendCborPost(SRVEntry{
		SrvURL: ctx.Value(CFG_ENV_GITHUB_CLIENTID).(string),
	}, IOPLOGGER_LOGGER_CMD, payloadBytes, &authzHeader)

	if err != nil {
		return err
	}

	if httpStatusCode != 200 {
		return fmt.Errorf("error submitting IOP logger event. HTTP status code: %d", httpStatusCode)
	}

	return nil
}
