package listener

import (
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	"github.com/google/uuid"
)

func NewDevice_RequestListenerInst(voucherEntry fdoshared.VoucherDBEntry, guid fdoshared.FdoGuid) RequestListenerInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RequestListenerInst{
		Uuid:        uuidBytes,
		Guid:        guid,
		TestVoucher: voucherEntry,
		Type:        fdoshared.Device,
		To1: RequestListenerRunnerInst{
			Protocol: fdoshared.To1,
			Tests: map[fdoshared.FdoCmd][]testcom.FDOTestID{
				fdoshared.TO1_30_HELLO_RV:    append(testcom.FIDO_LISTENER_30_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO1_32_PROVE_TO_RV: append(testcom.FIDO_LISTENER_32_LIST, testcom.FIDO_LISTENER_POSITIVE),
			},
			Running:        false,
			TestRunHistory: []ListenerTestRun{},
		},
		To2: RequestListenerRunnerInst{
			Protocol: fdoshared.To2,
			Tests: map[fdoshared.FdoCmd][]testcom.FDOTestID{
				fdoshared.TO2_60_HELLO_DEVICE:              append(testcom.FIDO_LISTENER_60_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO2_62_GET_OVNEXTENTRY:           append(testcom.FIDO_LISTENER_62_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO2_64_PROVE_DEVICE:              append(testcom.FIDO_LISTENER_64_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY: append(testcom.FIDO_LISTENER_66_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO2_68_DEVICE_SERVICE_INFO:       append(testcom.FIDO_LISTENER_68_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO2_70_DONE:                      append(testcom.FIDO_LISTENER_70_LIST, testcom.FIDO_LISTENER_POSITIVE),
			},
			Running:        false,
			TestRunHistory: []ListenerTestRun{},
		},
	}
}

func NewDO_RequestListenerInst(voucherEntry fdoshared.VoucherDBEntry, guid fdoshared.FdoGuid) RequestListenerInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RequestListenerInst{
		Uuid:        uuidBytes,
		Guid:        guid,
		TestVoucher: voucherEntry,
		Type:        fdoshared.DeviceOnboardingService,
		To0: RequestListenerRunnerInst{
			Protocol: fdoshared.To0,
			Tests: map[fdoshared.FdoCmd][]testcom.FDOTestID{
				fdoshared.TO0_20_HELLO:      append(testcom.FIDO_LISTENER_20_LIST, testcom.FIDO_LISTENER_POSITIVE),
				fdoshared.TO0_22_OWNER_SIGN: append(testcom.FIDO_LISTENER_22_LIST, testcom.FIDO_LISTENER_POSITIVE),
			},
			Running:        false,
			TestRunHistory: []ListenerTestRun{},
		},
	}
}
