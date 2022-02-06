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

	// TO2_ // TODO
	// TO2_
	// TO2_
	// TO2_
	// TO2_
	// TO2_
	// TO2_

	TO_ERROR_255 FdoCmd = 255
)

type FdoToProtocol int

const (
	To0 FdoToProtocol = 0
	To1 FdoToProtocol = 1
	To2 FdoToProtocol = 2
)
