package testexec

import (
	"log"

	"github.com/fido-alliance/iot-fdo-conformance-tools/core/device/to2"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	testdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/request"
)

func preExecuteTo2_68(reqte reqtestsdeps.RequestTestInst) (*to2.To2Requestor, error) {
	testCred, err := reqte.TestVouchers.GetVoucher(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	// Generating TO0 handler
	to2requestor := to2.NewTo2Requestor(fdoshared.SRVEntry{
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

	err = to2requestor.ProveOVHdr61PubKey.Equal(loePubKey)
	if err != nil {
		return nil, err
	}

	// 64
	_, _, err = to2requestor.ProveDevice64(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	_, _, err = to2requestor.DeviceServiceInfoReady66(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	return &to2requestor, nil

}

func executeTo2_68(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_DOT_68 {
		to2requestor, err := preExecuteTo2_68(reqte)
		if err != nil {
			reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
				Passed: false,
				Error:  "Error running TO2 DeviceServiceInfoReady66 batch. Pre setup failed. " + err.Error(),
			})
			return
		}

		switch testId {
		case testcom.FIDO_DOT_68_POSITIVE:
			var deviceSims []fdoshared.ServiceInfoKV = fdoshared.GetDeviceOSSims()

			for i, deviceSim := range deviceSims {
				deviceInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo: []fdoshared.ServiceInfoKV{
						deviceSim,
					},
					IsMoreServiceInfo: i+1 <= len(deviceSims),
				}
				_, _, err := to2requestor.DeviceServiceInfo68(deviceInfo, testcom.NULL_TEST)
				if err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}
			}

			maxCounter := 255
			for {
				ownerSim, _, err := to2requestor.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
					ServiceInfo:       []fdoshared.ServiceInfoKV{},
					IsMoreServiceInfo: false,
				}, testcom.NULL_TEST)
				if err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}

				log.Println("Receiving OwnerSim DeviceServiceInfo68")

				if ownerSim.IsDone {
					break
				}

				maxCounter = maxCounter - 1
				if maxCounter <= 0 {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  "Error running positive test. Owner sent more than 255 SIMs",
					})
					return
				}
			}

			reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
				Passed: true,
			})

		default:
			var testState *testcom.FDOTestState
			var deviceSims []fdoshared.ServiceInfoKV = fdoshared.GetDeviceOSSims()

			randomIndex := fdoshared.NewRandomInt(0, len(deviceSims)-1)
			for i, deviceSim := range deviceSims {
				selectedTestId := testcom.NULL_TEST

				deviceInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo: []fdoshared.ServiceInfoKV{
						deviceSim,
					},
					IsMoreServiceInfo: i+1 <= len(deviceSims),
				}

				if randomIndex == i {
					selectedTestId = testId
				}

				if testId == testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC {
					selectedTestId = testcom.NULL_TEST
				}

				_, testState, err = to2requestor.DeviceServiceInfo68(deviceInfo, selectedTestId)
				if testState == nil && err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}

				if testState != nil {
					break
				}
			}

			if testState != nil {
				reqtDB.ReportTest(reqte.Uuid, testId, *testState)
				continue
			}

			maxCounter := 255
			for {
				selectedTestId := testcom.NULL_TEST

				getOwnerInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo:       nil,
					IsMoreServiceInfo: false,
				}

				if testId == testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC && maxCounter != 255 {
					selectedTestId = testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC

					getOwnerInfo.ServiceInfo = []fdoshared.ServiceInfoKV{
						deviceSims[fdoshared.NewRandomInt(0, len(deviceSims)-1)],
					}

					getOwnerInfo.IsMoreServiceInfo = true
				}

				_, testState, err := to2requestor.DeviceServiceInfo68(getOwnerInfo, selectedTestId)
				if testState == nil && err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}

				log.Println("Receiving OwnerSim DeviceServiceInfo68")

				if testId == testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC && maxCounter != 255 {
					reqtDB.ReportTest(reqte.Uuid, testId, *testState)
					break
				}

				maxCounter = maxCounter - 1
				if maxCounter <= 0 {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  "Error running test. Too many SIMs or retries.",
					})
					return
				}
			}
		}
	}
}
