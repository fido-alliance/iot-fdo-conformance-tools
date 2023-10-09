package rv

import (
	"context"
	"net/http"

	"github.com/dgraph-io/badger/v4"
)

func SetupServer(db *badger.DB, ctx context.Context) {
	to0 := NewRvTo0(db, ctx)
	to1 := NewRvTo1(db, ctx)

	http.HandleFunc("/fdo/101/msg/20", to0.Handle20Hello)
	http.HandleFunc("/fdo/101/msg/22", to0.Handle22OwnerSign)
	http.HandleFunc("/fdo/101/msg/30", to1.Handle30HelloRV)
	http.HandleFunc("/fdo/101/msg/32", to1.Handle32ProveToRV)
}
