package testexec

import (
	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func executeTo2_60_Vouchers(reqte req_tests_deps.RequestTestInst, reqtDB *dbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_VOUCHER {
		testCred, err := reqte.TestVouchers.GetVoucher(testId)
		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  "Error getting voucher for TO2 60. " + err.Error(),
			}

			reqtDB.ReportTest(reqte.Uuid, testId, errTestState)
			return
		}

		// Generating TO0 handler
		to2requestor := fdodeviceimplementation.NewTo2Requestor(fdodeviceimplementation.SRVEntry{
			SrvURL: reqte.URL,
		}, testCred.WawDeviceCredential, fdoshared.KEX_ECDH256, fdoshared.CIPHER_A128GCM) // TODO

		_, rvtTestState, err := to2requestor.HelloDevice60(testId)

		if rvtTestState == nil && err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  err.Error(),
			}

			rvtTestState = &errTestState
		}

		reqtDB.ReportTest(reqte.Uuid, testId, *rvtTestState)
	}

}
