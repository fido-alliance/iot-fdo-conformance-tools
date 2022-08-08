package fdodo

import (
	"net/http"

	"github.com/WebauthnWorks/fdo-do/dbs"
	"github.com/WebauthnWorks/fdo-do/to2"
	"github.com/dgraph-io/badger/v3"
)

func SetupServer(db *badger.DB) {
	DoTo2 := to2.DoTo2{
		Session: dbs.NewSessionDB(db),
		Voucher: dbs.NewVoucherDB(db),
	}

	http.HandleFunc("/fdo/101/msg/60", DoTo2.HelloDevice60)
	http.HandleFunc("/fdo/101/msg/62", DoTo2.GetOVNextEntry62)
	http.HandleFunc("/fdo/101/msg/64", DoTo2.ProveDevice64)
	http.HandleFunc("/fdo/101/msg/66", DoTo2.DeviceServiceInfoReady66)
	http.HandleFunc("/fdo/101/msg/68", DoTo2.DeviceServiceInfo68)
	http.HandleFunc("/fdo/101/msg/70", DoTo2.Done70)
}
