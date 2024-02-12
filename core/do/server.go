package do

import (
	"context"
	"net/http"

	"github.com/dgraph-io/badger/v4"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do/to2"
)

func SetupServer(db *badger.DB, ctx context.Context) {
	doto2 := to2.NewDoTo2(db, ctx)

	http.HandleFunc("/fdo/101/msg/60", doto2.HelloDevice60)
	http.HandleFunc("/fdo/101/msg/62", doto2.GetOVNextEntry62)
	http.HandleFunc("/fdo/101/msg/64", doto2.ProveDevice64)
	http.HandleFunc("/fdo/101/msg/66", doto2.DeviceServiceInfoReady66)
	http.HandleFunc("/fdo/101/msg/68", doto2.DeviceServiceInfo68)
	http.HandleFunc("/fdo/101/msg/70", doto2.Done70)
}
