package testexec

import (
	"github.com/WebauthnWorks/fdo-do/to0"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

var rv20Tests []testcom.FDOTestID = []testcom.FDOTestID{
	testcom.FIDO_RVT_20_BAD_ENCODING,
	testcom.FIDO_RVT_21_CHECK_RESP,
	testcom.FIDO_RVT_20_POSITIVE,
}

var rv22Tests []testcom.FDOTestID = []testcom.FDOTestID{
	testcom.FIDO_RVT_22_BAD_ENCODING,
	testcom.FIDO_RVT_23_CHECK_RESP,
	testcom.FIDO_RVT_23_POSITIVE,
}

func ExecuteRVTests(reqte req_tests_deps.RequestTestInstDBEntry, reqtDB *dbs.RequestTestDB, devDB *dbs.DeviceBaseDB) {
	reqtDB.StartNewRun(reqte.Uuid)

	for _, rv20test := range rv20Tests {
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
		}, testCredV.VoucherDBEntry)

		switch rv20test {
		case testcom.FIDO_RVT_20_BAD_ENCODING, testcom.FIDO_RVT_21_CHECK_RESP:
			_, rvtTestState, err := to0inst.Hello20(rv20test)

			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv20test, *rvtTestState)

		case testcom.FIDO_RVT_20_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to0inst.Hello20(testcom.NULL_TEST)
			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv20test, errTestState)
				return
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv20test, errTestState)
			}

		}
	}

	for _, rv22test := range rv22Tests {
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
		}, testCredV.VoucherDBEntry)

		switch rv22test {
		case testcom.FIDO_RVT_22_BAD_ENCODING, testcom.FIDO_RVT_23_CHECK_RESP:
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

			_, rvtTestState, err := to0inst.OwnerSign22(helloAck.NonceTO0Sign, rv22test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv22test, *rvtTestState)

		case testcom.FIDO_RVT_23_POSITIVE:
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

			_, _, err = to0inst.OwnerSign22(helloAck.NonceTO0Sign, testcom.NULL_TEST)
			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
				return
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, rv22test, errTestState)
			}
		}
	}

	reqtDB.FinishRun(reqte.Uuid)
}
