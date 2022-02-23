package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli/v2"
)

const PORT = 8080

type StoredVoucher struct {
	VoucherEntry VoucherDBEntry
	RVURL        string
	WaitSeconds  uint32
}

func StartServer(db *badger.DB) {
	voucher := Voucher{
		session: &SessionDB{
			db: db,
		},
	}
	DoTo2 := DoTo2{
		Session: &SessionDB{
			db: db,
		},
	}

	http.HandleFunc("/fdo/voucher", voucher.saveVoucher)
	http.HandleFunc("/fdo/101/msg/60", DoTo2.HelloDevice60)
	http.HandleFunc("/fdo/101/msg/62", DoTo2.GetOVNextEntry62)
	http.HandleFunc("/fdo/101/msg/64", DoTo2.ProveDevice64)
	http.HandleFunc("/fdo/101/msg/66", DoTo2.DeviceServiceInfoReady66)
	http.HandleFunc("/fdo/101/msg/68", DoTo2.DeviceServiceInfo68)
	http.HandleFunc("/fdo/101/msg/70", DoTo2.Done70)

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
				Usage: "Starts do",
				Action: func(c *cli.Context) error {
					StartServer(db)
					return nil
				},
			},
			{
				Name:  "ecdh",
				Usage: "Tests ech",
				Action: func(c *cli.Context) error {
					xAKeyExchange, priva := beginECDHKeyExchange(fdoshared.ECDH256)
					xBKeyExchange, privb := beginECDHKeyExchange(fdoshared.ECDH256)

					shSeDI := finishKeyExchange(xAKeyExchange, xBKeyExchange, *privb, false)
					shSeDO := finishKeyExchange(xBKeyExchange, xAKeyExchange, *priva, true)
					if bytes.Compare(shSeDI, shSeDO) != 0 {
						log.Panicln("Failed")
						return nil
					}
					log.Println("Success")
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
							RVURL:       "http://localhost:8086",
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

						// store voucher with guid here.
						dbtxn := db.NewTransaction(true)
						defer dbtxn.Discard()

						ovHeader, err := voucher.Voucher.GetOVHeader()
						if err != nil {
							log.Println("failed")
						}

						// needs to be refactored into seperate function
						storedVoucher := StoredVoucher{
							VoucherEntry: voucher,
							RVURL:        "http://localhost:8083",
							WaitSeconds:  acceptOwner23.WaitSeconds,
						}
						var voucherBytes []byte
						voucherBytes, err = cbor.Marshal(storedVoucher)
						if err != nil {
							log.Panicln("error marshaling")
						}

						entry := badger.NewEntry(ovHeader.OVGuid[:], voucherBytes).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
						err = dbtxn.SetEntry(entry)
						if err != nil {
							log.Panicln("Failed creating session db entry %s", err.Error())
							// return []byte{}, errors.New("Failed creating session db entry instance. The error is: " + err.Error())
						}

						dbtxn.Commit()
						if err != nil {
							log.Panicln("Failed saving session entry. The error is: %s", err.Error())
						}

						log.Println(acceptOwner23)
						log.Println(hex.EncodeToString(ovHeader.OVGuid[:]))
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
