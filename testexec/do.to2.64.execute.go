package testexec

import (
	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func preExecuteTo2_64(reqte req_tests_deps.RequestTestInst) (*fdodeviceimplementation.To2Requestor, error) {
	testCred, err := reqte.TestVouchers.GetVoucher(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	// Generating TO0 handler
	to2requestor := fdodeviceimplementation.NewTo2Requestor(fdodeviceimplementation.SRVEntry{
		SrvURL: reqte.URL,
	}, testCred.WawDeviceCredential, fdoshared.KEX_ECDH256, fdoshared.CIPHER_A128GCM) // TODO

	proveOVHdrPayload61, _, err := to2requestor.HelloDevice60(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	var ovEntries fdoshared.OVEntryArray
	for i := 0; i < int(proveOVHdrPayload61.NumOVEntries); i++ {
		nextEntry, _, err := to2requestor.GetOVNextEntry62(uint8(i), testcom.NULL_TEST)
		if err != nil {
			return nil, err

		}

		if nextEntry.OVEntryNum != uint8(i) {
			return nil, err
		}

		ovEntries = append(ovEntries, nextEntry.OVEntry)
	}

	err = ovEntries.VerifyEntries(proveOVHdrPayload61.OVHeader, proveOVHdrPayload61.HMac)
	if err != nil {
		return nil, err
	}

	lastOvEntry := ovEntries[len(ovEntries)-1]
	loePubKey, _ := lastOvEntry.GetOVEntryPubKey()

	err = to2requestor.ProveOVHdr61PubKey.Equals(loePubKey)
	if err != nil {
		return nil, err
	}

	return &to2requestor, nil

}

func executeTo2_64(reqte req_tests_deps.RequestTestInst, reqtDB *dbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_DOT_60 {
		to2requestor, err := preExecuteTo2_64(reqte)
		if err != nil {
			reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
				Passed: false,
				Error:  "Error running TO2 ProveDevice64 batch. Pre setup failed. " + err.Error(),
			})
			return
		}

		switch testId {
		case testcom.FIDO_DOT_64_POSITIVE:
			var errTestState testcom.FDOTestState
			_, _, err := to2requestor.ProveDevice64(testId)
			if err != nil {
				errTestState = testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}
				reqtDB.ReportTest(reqte.Uuid, testId, errTestState)
				return
			} else {
				errTestState = testcom.FDOTestState{
					Passed: true,
				}
				reqtDB.ReportTest(reqte.Uuid, testId, errTestState)
			}

		default:
			_, rvtTestState, err := to2requestor.ProveDevice64(testId)
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
}
