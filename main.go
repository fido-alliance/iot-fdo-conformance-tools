package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	fdorv "github.com/WebauthnWorks/fdo-rv"
	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli/v2"
)

const PORT = 8080

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
				Usage: "Starts do",
				Action: func(c *cli.Context) error {
					// Setup FDO listeners
					fdodo.SetupServer(db)
					fdorv.SetupServer(db)
					externalapi.SetupServer(db)

					log.Printf("Starting server at port %d... \n", PORT)

					err := http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil)
					if err != nil {
						log.Panicln("Error starting HTTP server. " + err.Error())
					}
					return nil
				},
			},
			{
				Name:  "testto0",
				Usage: "",
				Action: func(c *cli.Context) error {

					// voucherDb := fdodbs.NewVoucherDB(db)

					// vouchers, err := fdodo.LoadLocalVouchers()
					// if err != nil {
					// 	log.Panic(err)
					// }

					// for _, voucher := range vouchers {
					// 	to0requestor := fdodo.NewTo0Requestor(fdodo.RVEntry{
					// 		RVURL:       "http://localhost:8083",
					// 		AccessToken: "",
					// 	}, voucher)

					// 	helloack21, err := to0requestor.Hello20()
					// 	if err != nil {
					// 		log.Panic(err)
					// 	}

					// 	acceptOwner23, err := to0requestor.OwnerSign22(helloack21.NonceTO0Sign)
					// 	if err != nil {
					// 		log.Panic(err)
					// 	}

					// 	err = voucherDb.Save(fdoshared.VoucherDBEntry{
					// 		Voucher:        voucher.Voucher,
					// 		PrivateKeyX509: voucher.PrivateKeyX509,
					// 	})
					// 	if err != nil {
					// 		log.Panic(err)
					// 	}

					// 	ovHeader, _ := voucher.Voucher.GetOVHeader()

					// 	log.Println(acceptOwner23)
					// 	log.Println(hex.EncodeToString(ovHeader.OVGuid[:]))
					// }

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
