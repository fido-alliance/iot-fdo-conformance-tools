package testexec

import (
	"log"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-do/to0"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

func ExecuteRVTestsTo1(reqte reqtestsdeps.RequestTestInst, reqtDB *dbs.RequestTestDB, devDB *dbs.DeviceBaseDB) {
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
	}, testCredV.VoucherDBEntry)

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

	to1inst := fdodeviceimplementation.NewTo1Requestor(fdodeviceimplementation.SRVEntry{
		SrvURL: reqte.URL,
	}, testCredV.WawDeviceCredential)

	// Starting tests
	for _, rv30test := range testcom.FIDO_TEST_LIST_DEVT_30 {
		switch rv30test {
		case testcom.FIDO_DEVT_30_BAD_ENCODING, testcom.FIDO_DEVT_30_BAD_UNKNOWN_GUID, testcom.FIDO_DEVT_30_BAD_SIGINFO:
			_, rvtTestState, err := to1inst.HelloRV30(rv30test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv30test, *rvtTestState)

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
			log.Printf("Skipping \"%s\" test...", rv30test)

		}
	}

	for _, rv32test := range testcom.FIDO_TEST_LIST_DEVT_32 {
		switch rv32test {
		case testcom.FIDO_DEVT_32_BAD_PROVE_TO_RV_PAYLOAD_ENCODING, testcom.FIDO_DEVT_32_BAD_ENCODING, testcom.FIDO_DEVT_32_BAD_SIGNATURE, testcom.FIDO_DEVT_33_CHECK_RESP, testcom.FIDO_DEVT_32_BAD_TO1PROOF_NONCE:
			_, rvtTestState, err := to1inst.HelloRV30(rv32test)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, rv32test, *rvtTestState)

		case testcom.FIDO_DEVT_33_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to1inst.HelloRV30(rv32test)

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
			log.Printf("Skipping \"%s\" test...", rv32test)

		}
	}

	reqtDB.FinishRun(reqte.Uuid)
}
