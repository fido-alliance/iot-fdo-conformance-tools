package testexec

import (
	"errors"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

func preExecuteTo2_70(reqte reqtestsdeps.RequestTestInst) (*fdodeviceimplementation.To2Requestor, error) {
	testCred, err := reqte.TestVouchers.GetVoucher(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	// Generating TO2 handler
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
			return nil, err
		}
	}

	maxCounter := 255
	for {
		ownerSim, _, err := to2requestor.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
			ServiceInfo:       nil,
			IsMoreServiceInfo: false,
		}, testcom.NULL_TEST)
		if err != nil {
			return nil, err
		}

		ownerSims = append(ownerSims, *ownerSim.ServiceInfo)

		if ownerSim.IsDone {
			break
		}

		maxCounter = maxCounter - 1
		if maxCounter <= 0 {
			return nil, errors.New("Error running positive test. Owner sent more than 255 SIMs")
		}
	}

	return &to2requestor, nil
}

func executeTo2_70(reqte reqtestsdeps.RequestTestInst, reqtDB *dbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_DOT_68 {
		to2requestor, err := preExecuteTo2_68(reqte)
		if err != nil {
			reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
				Passed: false,
				Error:  "Error running TO2 batch. Pre setup failed. " + err.Error(),
			})
			return
		}

		switch testId {
		case testcom.FIDO_DOT_70_POSITIVE:
			_, _, err = to2requestor.Done70(testcom.NULL_TEST)
			if err != nil {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				})
				return
			} else {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: true,
				})
			}

		default:
			_, rvtTestState, err := to2requestor.Done70(testId)
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
