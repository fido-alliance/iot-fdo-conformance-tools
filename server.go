package fdorv

import (
	"net/http"

	"github.com/dgraph-io/badger/v3"
)

func SetupServer(db *badger.DB) {
	to0 := RvTo0{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
	}

	to1 := RvTo1{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
	}

	http.HandleFunc("/fdo/101/msg/20", to0.Handle20Hello)
	http.HandleFunc("/fdo/101/msg/22", to0.Handle22OwnerSign)
	http.HandleFunc("/fdo/101/msg/30", to1.Handle30HelloRV)
	http.HandleFunc("/fdo/101/msg/32", to1.Handle32ProveToRV)
}
