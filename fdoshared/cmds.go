package fdoshared

import "strconv"

type FdoCmd uint8

func (h FdoCmd) ToString() string {
	return strconv.FormatUint(uint64(h), 10)
}

const (
	TO0_HELLO_20        FdoCmd = 20
	TO0_HELLO_ACK_21    FdoCmd = 21
	TO0_OWNER_SIGN_22   FdoCmd = 22
	TO0_ACCEPT_OWNER_23 FdoCmd = 23

	TO1_HELLO_RV_30     FdoCmd = 30
	TO1_HELLO_RV_ACK_31 FdoCmd = 31
	TO1_PROVE_TO_RV_32  FdoCmd = 32
	TO1_RV_REDIRECT_33  FdoCmd = 33

	TO2_HELLO_DEVICE_60              FdoCmd = 60
	TO2_PROVE_OVHDR_61               FdoCmd = 61
	TO2_GET_OVNEXTENTRY_62           FdoCmd = 62
	TO2_OV_NEXTENTRY_63              FdoCmd = 63
	TO2_PROVE_DEVICE_64              FdoCmd = 64
	TO2_SETUP_DEVICE_65              FdoCmd = 65
	TO2_DEVICE_SERVICE_INFO_READY_66 FdoCmd = 66
	TO2_OWNER_SERVICE_INFO_READY_67  FdoCmd = 67
	TO2_DEVICE_SERVICE_INFO_68       FdoCmd = 68
	TO2_OWNER_SERVICE_INFO_69        FdoCmd = 69
	TO2_DONE_70                      FdoCmd = 70
	TO2_DONE2_71                     FdoCmd = 71

	TO_ERROR_255 FdoCmd = 255
)

type FdoToProtocol int

const (
	To0 FdoToProtocol = 0
	To1 FdoToProtocol = 1
	To2 FdoToProtocol = 2
)
