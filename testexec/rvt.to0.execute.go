package testexec

import (
	"log"

	"github.com/WebauthnWorks/fdo-do/to0"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

func ExecuteRVTestsTo0(reqte req_tests_deps.RequestTestInst, reqtDB *dbs.RequestTestDB, devDB *dbs.DeviceBaseDB) {
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
		}, testCredV.VoucherDBEntry)

		switch rv22test {

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

		default:
			log.Printf("Skipping \"\" test...", rv22test)
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
		}, testCredV.VoucherDBEntry)

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
