package testexec

import (
	"context"

	"github.com/fido-alliance/fdo-fido-conformance-server/core/do/to0"
	testdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"

	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	reqtestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/request"
)

func ExecuteRVTestsTo0(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB, devDB *dbs.DeviceBaseDB, ctx context.Context) {
	reqtDB.StartNewRun(reqte.Uuid)

	for _, rv20test := range testcom.FIDO_TEST_LIST_RVT_20 {
		randomGuid := reqte.FdoSeedIDs.GetRandomTestGuid()
		testCredV, err := devDB.GetVANDV(randomGuid, rv20test)

		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}

			reqtDB.ReportTest(reqte.Uuid, rv20test, errTestState)
			continue
		}

		to0inst := to0.NewTo0Requestor(to0.RVEntry{
			RVURL: reqte.URL,
		}, testCredV.VoucherDBEntry, ctx)

		switch rv20test {
		case testcom.FIDO_RVT_20_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to0inst.Hello20(testcom.NULL_TEST)
			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv20test, errTestState)
				continue
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv20test, errTestState)
			}

		default:
			_, testState, err := to0inst.Hello20(rv20test)
			if testState == nil && err != nil {
				testState = &testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
			}

			reqtDB.ReportTest(reqte.Uuid, rv20test, *testState)
		}
	}

	for _, rv22test := range testcom.FIDO_TEST_LIST_RVT_22 {
		randomGuid := reqte.FdoSeedIDs.GetRandomTestGuid()
		testCredV, err := devDB.GetVANDV(randomGuid, rv22test)

		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}

			reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
			continue
		}

		to0inst := to0.NewTo0Requestor(to0.RVEntry{
			RVURL: reqte.URL,
		}, testCredV.VoucherDBEntry, ctx)

		var errTestState testcom.FDOTestState
		helloAck, _, err := to0inst.Hello20(testcom.NULL_TEST)
		if err != nil {
			errTestState = testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}
			reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
			continue
		}

		switch rv22test {
		case testcom.FIDO_RVT_23_POSITIVE:
			_, _, err = to0inst.OwnerSign22(helloAck.NonceTO0Sign, testcom.NULL_TEST)
			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
				continue
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
			}

		default:
			_, rvtTestState, err := to0inst.OwnerSign22(helloAck.NonceTO0Sign, rv22test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv22test, *rvtTestState)
		}
	}

	for _, rv22VoucherTest := range testcom.FIDO_TEST_LIST_VOUCHER {
		randomGuid := reqte.FdoSeedIDs.GetRandomTestGuid()
		testCredV, err := devDB.GetVANDV(randomGuid, rv22VoucherTest)
		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}

			reqtDB.ReportTest(reqte.Uuid, rv22VoucherTest, errTestState)
			continue
		}

		to0inst := to0.NewTo0Requestor(to0.RVEntry{
			RVURL: reqte.URL,
		}, testCredV.VoucherDBEntry, ctx)

		var errTestState testcom.FDOTestState
		helloAck, _, err := to0inst.Hello20(testcom.NULL_TEST)
		if err != nil {
			errTestState = testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}
			reqtDB.ReportTest(reqte.Uuid, rv22VoucherTest, errTestState)
			continue
		}

		_, rvtTestState, err := to0inst.OwnerSign22(helloAck.NonceTO0Sign, rv22VoucherTest)
		if rvtTestState == nil && err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}

			rvtTestState = &errTestState
		}

		reqtDB.ReportTest(reqte.Uuid, rv22VoucherTest, *rvtTestState)
	}

	reqtDB.FinishRun(reqte.Uuid)
}
