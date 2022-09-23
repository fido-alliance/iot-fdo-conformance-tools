package testexec

import (
	"log"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func preExecuteTo2_68(reqte req_tests_deps.RequestTestInst) (*fdodeviceimplementation.To2Requestor, error) {
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

func executeTo2_68(reqte req_tests_deps.RequestTestInst, reqtDB *dbs.RequestTestDB) {
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
			var deviceSims []fdoshared.ServiceInfoKV = []fdoshared.ServiceInfoKV{ //TODO
				{
					ServiceInfoKey: "device:test1",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test2",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test3",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test4",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test5",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test6",
					ServiceInfoVal: []byte("1234"),
				},
			}

			var ownerSims []fdoshared.ServiceInfoKV // TODO

			for i, deviceSim := range deviceSims {
				deviceInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo:       &deviceSim,
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
					ServiceInfo:       nil,
					IsMoreServiceInfo: false,
				}, testcom.NULL_TEST)
				if err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
					return
				}

				log.Println("Receiving OwnerSim DeviceServiceInfo68 " + ownerSim.ServiceInfo.ServiceInfoKey)

				ownerSims = append(ownerSims, *ownerSim.ServiceInfo)

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
			var deviceSims []fdoshared.ServiceInfoKV = []fdoshared.ServiceInfoKV{ //TODO
				{
					ServiceInfoKey: "device:test1",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test2",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test3",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test4",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test5",
					ServiceInfoVal: []byte("1234"),
				},
				{
					ServiceInfoKey: "device:test6",
					ServiceInfoVal: []byte("1234"),
				},
			}

			randomIndex := fdoshared.NewRandomInt(0, len(deviceSims)-1)
			for i, deviceSim := range deviceSims {
				selectedTestId := testcom.NULL_TEST

				deviceInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo:       &deviceSim,
					IsMoreServiceInfo: i+1 <= len(deviceSims),
				}

				if randomIndex == i {
					selectedTestId = testId
				}

				_, _, err := to2requestor.DeviceServiceInfo68(deviceInfo, selectedTestId)
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

				getOwnerInfo := fdoshared.DeviceServiceInfo68{
					ServiceInfo:       nil,
					IsMoreServiceInfo: false,
				}

				if testId == testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC && maxCounter != 255 {
					getOwnerInfo.ServiceInfo = &deviceSims[fdoshared.NewRandomInt(0, len(deviceSims)-1)]
					getOwnerInfo.IsMoreServiceInfo = true
				}

				_, testState, err := to2requestor.DeviceServiceInfo68(getOwnerInfo, testcom.NULL_TEST)
				if testState == nil && err != nil {
					reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
						Passed: false,
						Error:  err.Error(),
					})
				}

				if testId == testcom.FIDO_DOT_68_BAD_COMPLETION_LOGIC && maxCounter != 255 {
					reqtDB.ReportTest(reqte.Uuid, testId, *testState)
					break
				}
			}
		}
	}
}
