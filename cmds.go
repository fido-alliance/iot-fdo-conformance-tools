package fdoshared

import "strconv"

type FdoCmd uint8

func (h FdoCmd) ToString() string {
	return strconv.FormatUint(uint64(h), 10)
}

const (
	TO0_20_HELLO        FdoCmd = 20
	TO0_21_HELLO_ACK    FdoCmd = 21
	TO0_22_OWNER_SIGN   FdoCmd = 22
	TO0_23_ACCEPT_OWNER FdoCmd = 23

	TO1_30_HELLO_RV     FdoCmd = 30
	TO1_31_HELLO_RV_ACK FdoCmd = 31
	TO1_32_PROVE_TO_RV  FdoCmd = 32
	TO1_33_RV_REDIRECT  FdoCmd = 33

	TO2_60_HELLO_DEVICE              FdoCmd = 60
	TO2_61_PROVE_OVHDR               FdoCmd = 61
	TO2_62_GET_OVNEXTENTRY           FdoCmd = 62
	TO2_63_OV_NEXTENTRY              FdoCmd = 63
	TO2_64_PROVE_DEVICE              FdoCmd = 64
	TO2_65_SETUP_DEVICE              FdoCmd = 65
	TO2_66_DEVICE_SERVICE_INFO_READY FdoCmd = 66
	TO2_67_OWNER_SERVICE_INFO_READY  FdoCmd = 67
	TO2_68_DEVICE_SERVICE_INFO       FdoCmd = 68
	TO2_69_OWNER_SERVICE_INFO        FdoCmd = 69
	TO2_70_DONE                      FdoCmd = 70
	TO2_71_DONE2                     FdoCmd = 71

	VOUCHER_API FdoCmd = 101

	TO_ERROR_255 FdoCmd = 255
)

type FdoToProtocol int

const (
	To0 FdoToProtocol = 0
	To1 FdoToProtocol = 1
	To2 FdoToProtocol = 2
)
