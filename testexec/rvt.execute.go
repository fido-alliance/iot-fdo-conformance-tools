package testexec

import (
	"github.com/WebauthnWorks/fdo-do/to0"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/rvtdeps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

var rv20Tests []testcom.FDOTestID = []testcom.FDOTestID{
	testcom.FIDO_RVT_20_BAD_ENCODING,
	testcom.FIDO_RVT_21_CHECK_RESP,
}

func ExecuteRVTests(rvte rvtdeps.RendezvousServerTestDBEntry, rvtDB *dbs.RendezvousServerTestDB) error {
	rvtDB.StartNewRun(rvte.ID)

	to0inst := to0.NewTo0Requestor(to0.RVEntry{
		RVURL: rvte.URL,
	}, rvte.VDIs[0].VoucherDBEntry)

	for _, rv20test := range rv20Tests {
		reqCode := rv20test
		_, rvtTestState, err := to0inst.Hello20(&reqCode)
		if rvtTestState == nil && err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  "Error executing Hello20. " + err.Error(),
			}

			rvtTestState = &errTestState
		}

		rvtDB.ReportTest(rvte.ID, rv20test, *rvtTestState)
	}

	rvtDB.FinishRun(rvte.ID)

	return nil
}
