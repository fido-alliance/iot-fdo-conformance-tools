package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	fdorv "github.com/WebauthnWorks/fdo-rv"
	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli/v2"
)

const PORT = 8080

const RSAKEYS_LOCATION string = "./_randomKeys/"

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
				Usage: "Starts conformance server",
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
				Name:      "seed",
				Usage:     "Seed FDO Cred Base",
				UsageText: "Generates one hundred thousand cred bases to be used in testing",
				Action: func(c *cli.Context) error {
					devbasedb := dbs.NewDeviceBaseDB(db)
					configdb := dbs.NewConfigDB(db)

					return PreSeed(configdb, devbasedb)
				},
			},
			{
				Name: "resetUsers",
				Action: func(ctx *cli.Context) error {
					userDB := dbs.NewUserTestDB(db)

					userDB.ResetUsers()

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
