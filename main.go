package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	fdorv "github.com/WebauthnWorks/fdo-rv"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli/v2"
)

const PORT = 8080
const SeedingSize = 100000

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

					newConfig := dbs.MainConfig{
						SeededGuids: fdoshared.FdoSeedIDs{},
					}
					for _, sgType := range fdoshared.DeviceSgTypeList {
						newConfig.SeededGuids[sgType] = []fdoshared.FdoGuid{}

						if sgType == fdoshared.StEPID10 || sgType == fdoshared.StEPID11 {
							log.Println("EPID is not currently supported!")
							continue
						}

						log.Printf("----- SgType %d. -----\n", sgType)
						getSgAlgInfo, err := fdoshared.GetAlgInfoFromSgType(sgType)
						if err != nil {
							return errors.New("Error getting AlgInfo. " + err.Error())
						}

						for i := 0; i < SeedingSize; i++ {
							log.Printf("No %d: Generating device base %d... ", i, sgType)
							newDeviceBase, err := fdoshared.NewWawDeviceCredBase(getSgAlgInfo.HmacType, sgType)
							if err != nil {
								return fmt.Errorf("Error generating device base for sgType %d. " + err.Error())
							}

							err = devbasedb.Save(*newDeviceBase)
							if err != nil {
								return fmt.Errorf("Error saving device base. " + err.Error())
							}

							newConfig.SeededGuids[sgType] = append(newConfig.SeededGuids[sgType], newDeviceBase.FdoGuid)

							log.Println("OK\n")
						}
					}

					err = configdb.Save(newConfig)
					if err != nil {
						return fmt.Errorf("Error saving config. " + err.Error())
					}

					return nil
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
