package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli/v2"
)

const PORT = 8080

func StartServer(db *badger.DB) {
	// to0 := RvTo0{
	// 	session: &SessionDB{
	// 		db: db,
	// 	},
	// 	ownersignDB: &OwnerSignDB{
	// 		db: db,
	// 	},
	// }

	// to1 := RvTo1{
	// 	session: &SessionDB{
	// 		db: db,
	// 	},
	// 	ownersignDB: &OwnerSignDB{
	// 		db: db,
	// 	},
	// }

	// http.HandleFunc("/fdo/101/msg/20", to0.Handle20Hello)
	// http.HandleFunc("/fdo/101/msg/22", to0.Handle22OwnerSign)
	// http.HandleFunc("/fdo/101/msg/30", to1.Handle30HelloRV)
	// http.HandleFunc("/fdo/101/msg/32", to1.Handle32ProveToRV)

	log.Printf("Starting server at port %d... \n", PORT)

	err := http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil)
	if err != nil {
		log.Panicln("Error starting HTTP server. " + err.Error())
	}
}

func main() {
	options := badger.DefaultOptions("./badger.local.db")
	options.Logger = nil

	db, err := badger.Open(options)
	if err != nil {
		log.Panicln("Error opening Badger DB. " + err.Error())
	}
	defer db.Close()

	cliapp := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Starts rv",
				Action: func(c *cli.Context) error {
					StartServer(db)
					return nil
				},
			},
			{
				Name:  "ecdh",
				Usage: "Tests ech",
				Action: func(c *cli.Context) error {
					beginECDHKeyExchange(fdoshared.ECDH256)
					return nil
				},
			},
			{
				Name:  "testto0",
				Usage: "",
				Action: func(c *cli.Context) error {
					vouchers, err := LoadLocalVouchers()
					if err != nil {
						log.Panic(err)
					}

					for _, voucher := range vouchers {
						to0requestor := NewTo0Requestor(RVEntry{
							RVURL:       "http://localhost:8083",
							AccessToken: "",
						}, voucher)

						helloack21, err := to0requestor.Hello20()
						if err != nil {
							log.Panic(err)
						}

						acceptOwner23, err := to0requestor.OwnerSign22(helloack21.NonceTO0Sign)
						if err != nil {
							log.Panic(err)
						}

						log.Println(acceptOwner23)
					}

					return nil
				},
			},
			{
				Name:  "testloadvouchers",
				Usage: "",
				Action: func(c *cli.Context) error {

					_, err := LoadLocalVouchers()
					if err != nil {
						log.Panic(err)
					}

					return nil
				},
			},
		},
	}

	err = cliapp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
