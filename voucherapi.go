package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
)

const VOUCHERS_LOCATION string = "./_test_vouchers/"

type Voucher struct {
	session *SessionDB
}

//  Can write some checking...
func (h *Voucher) saveVoucher(w http.ResponseWriter, r *http.Request) {
	log.Println("save voucher")

	voucherFileBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_HELLO_DEVICE_60, "Failed to read body!", http.StatusBadRequest)
		return
	}
	log.Println(voucherFileBytes)

	voucherWriteLocation := fmt.Sprintf("%s%s.voucher.pem", VOUCHERS_LOCATION, "voucher1")
	err = os.WriteFile(voucherWriteLocation, voucherFileBytes, 0644)
	if err != nil {
		log.Println("fail")
	}

}
