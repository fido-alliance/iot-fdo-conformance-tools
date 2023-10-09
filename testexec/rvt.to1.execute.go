package testexec

import (
	"context"

	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/to1"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/do/to0"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	testdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/request"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
)

func ExecuteRVTestsTo1(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB, devDB *dbs.DeviceBaseDB, ctx context.Context) {
	reqtDB.StartNewRun(reqte.Uuid)

	// Generating voucher
	randomGuid := reqte.FdoSeedIDs.GetRandomTestGuid()
	testCredV, err := devDB.GetVANDV(randomGuid, testcom.NULL_TEST)

	if err != nil {
		errTestState := testcom.FDOTestState{
			Passed: false,
			Error:  err.Error(),
		}

		reqtDB.ReportTest(reqte.Uuid, testcom.NULL_TO1_SETUP, errTestState)
		return
	}

	// Generating TO0 handler
	to0inst := to0.NewTo0Requestor(to0.RVEntry{
		RVURL: reqte.URL,
	}, testCredV.VoucherDBEntry, ctx)

	// Enroling voucher
	var errTestState testcom.FDOTestState
	helloAck, _, err := to0inst.Hello20(testcom.NULL_TEST)
	if err != nil {
		errTestState = testcom.FDOTestState{
			Passed: false,
			Error:  err.Error(),
		}
		reqtDB.ReportTest(reqte.Uuid, testcom.NULL_TO1_SETUP, errTestState)
		return
	}

	_, _, err = to0inst.OwnerSign22(helloAck.NonceTO0Sign, testcom.NULL_TEST)
	if err != nil {
		errTestState = testcom.FDOTestState{
			Passed: false,
			Error:  err.Error(),
		}
		reqtDB.ReportTest(reqte.Uuid, testcom.NULL_TO1_SETUP, errTestState)
		return
	}

	to1inst := to1.NewTo1Requestor(fdoshared.SRVEntry{
		SrvURL: reqte.URL,
	}, testCredV.WawDeviceCredential)

	// Starting tests
	for _, rv30test := range testcom.FIDO_TEST_LIST_DEVT_30 {
		switch rv30test {

		case testcom.FIDO_DEVT_30_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to1inst.HelloRV30(rv30test)

			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv30test, errTestState)
				return
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv30test, errTestState)
			}

		default:
			_, rvtTestState, err := to1inst.HelloRV30(rv30test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv30test, *rvtTestState)
		}
	}

	for _, rv32test := range testcom.FIDO_TEST_LIST_DEVT_32 {
		helloRvAck31, _, err := to1inst.HelloRV30(testcom.NULL_TEST)
		if err != nil {
			errTestState = testcom.FDOTestState{
				Passed: false,
				Error:  "Error running test. Hello RV30 failed!" + err.Error(),
			}
			reqtDB.ReportTest(reqte.Uuid, rv32test, errTestState)
			continue
		}

		switch rv32test {

		case testcom.FIDO_DEVT_33_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to1inst.ProveToRV32(*helloRvAck31, rv32test)

			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv32test, errTestState)
				return
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv32test, errTestState)
			}

		default:
			_, rvtTestState, err := to1inst.ProveToRV32(*helloRvAck31, rv32test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv32test, *rvtTestState)
		}
	}

	reqtDB.FinishRun(reqte.Uuid)
}
