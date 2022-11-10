package testexec

import (
	"fmt"
	"log"

	fdodocommon "github.com/WebauthnWorks/fdo-device-implementation/common"
	"github.com/WebauthnWorks/fdo-device-implementation/to2"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/WebauthnWorks/fdo-shared/testcom"
	testdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/request"
)

func executeTo2_62(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_DOT_62 {
		testCred, err := reqte.TestVouchers.GetVoucher(testcom.NULL_TEST)
		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  "Error getting voucher for TO2 60. " + err.Error(),
			}

			reqtDB.ReportTest(reqte.Uuid, testcom.NULL_TEST, errTestState)
			return
		}

		// Generating TO0 handler
		to2requestor := to2.NewTo2Requestor(fdodocommon.SRVEntry{
			SrvURL: reqte.URL,
		}, testCred.WawDeviceCredential, fdoshared.KEX_ECDH256, fdoshared.CIPHER_A128GCM) // TODO

		proveOVHdrPayload61, _, err := to2requestor.HelloDevice60(testcom.NULL_TEST)
		if err != nil {
			errTestState := testcom.FDOTestState{
				Passed: false,
				Error:  "Error running TO2 GetOVNextEntry62 tests. Failed to run HelloDevice60. " + err.Error(),
			}
			reqtDB.ReportTest(reqte.Uuid, testcom.NULL_TEST, errTestState)
			return
		}

		switch testId {
		case testcom.FIDO_DOT_62_POSITIVE:

			var ovEntries fdoshared.OVEntryArray
			for i := 0; i < int(proveOVHdrPayload61.NumOVEntries); i++ {
				nextEntry, _, err := to2requestor.GetOVNextEntry62(uint8(i), testId)
				if err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}

				if nextEntry.OVEntryNum != uint8(i) {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  fmt.Sprintf("Server returned unexpected nextOvEntry. Expected %d. Got %d", i, nextEntry.OVEntryNum),
					})
					return
				}

				ovEntries = append(ovEntries, nextEntry.OVEntry)
			}

			err = ovEntries.VerifyEntries(proveOVHdrPayload61.OVHeader, proveOVHdrPayload61.HMac)
			if err != nil {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				})
				return
			}

			lastOvEntry := ovEntries[len(ovEntries)-1]
			loePubKey, _ := lastOvEntry.GetOVEntryPubKey()

			err = to2requestor.ProveOVHdr61PubKey.Equals(loePubKey)
			if err != nil {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				})
				return
			}

			errTestState := testcom.FDOTestState{
				Passed: true,
			}
			reqtDB.ReportTest(reqte.Uuid, testId, errTestState)

		default:
			randomTestIndex := fdoshared.NewRandomInt(0, int(proveOVHdrPayload61.NumOVEntries))
			for i := 0; i < int(proveOVHdrPayload61.NumOVEntries); i++ {
				selectedTestId := testcom.NULL_TEST
				selectedNextEntry := i
				if randomTestIndex == i {
					if testId == testcom.FIDO_DOT_62_BAD_ENCODING {
						selectedTestId = testId
					}

					if testId == testcom.FIDO_DOT_62_GETOVNEXT_BAD_INDEX {
						selectedNextEntry = fdoshared.NewRandomInt(int(proveOVHdrPayload61.NumOVEntries), 255)
					}
				}

				log.Printf("Requesting GetOVNextEntry62 for entry %d \n", i)
				_, testState, err := to2requestor.GetOVNextEntry62(uint8(selectedNextEntry), selectedTestId)
				if testState == nil && err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
				}

				if randomTestIndex == i {
					reqtDB.ReportTest(reqte.Uuid, testId, *testState)
				}
			}
		}
	}
}
