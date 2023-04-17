package testexec

import (
	fdodocommon "github.com/fido-alliance/fdo-fido-conformance-server/core/device/common"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/to2"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	testdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/request"
)

func executeTo2_60_Vouchers(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
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
		to2requestor := to2.NewTo2Requestor(fdodocommon.SRVEntry{
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
