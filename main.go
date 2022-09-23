package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
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
				Name: "testVoucherGen",
				Action: func(ctx *cli.Context) error {
					for _, sgType := range fdoshared.DeviceSgTypeList {
						if sgType == fdoshared.StEPID10 || sgType == fdoshared.StEPID11 {
							log.Println("EPID is not currently supported!")
							continue
						}

						log.Printf("----- SgType %d. -----\n", sgType)
						getSgAlgInfo, err := fdoshared.GetAlgInfoFromSgType(sgType)
						if err != nil {
							return errors.New("Error getting AlgInfo. " + err.Error())
						}

						for i := 0; i < 10; i++ {
							log.Printf("No %d: Generating device base %d... ", i, sgType)
							newDeviceBase, err := fdoshared.NewWawDeviceCredBase(getSgAlgInfo.HmacType, sgType)
							if err != nil {
								return fmt.Errorf("Error generating device base for sgType %d. " + err.Error())
							}

							start := time.Now()

							log.Printf("No %d: Generating voucher %d... ", i, sgType)
							_, err = fdodeviceimplementation.NewVirtualDeviceAndVoucher(*newDeviceBase, testcom.NULL_TEST)
							if err != nil {
								log.Panicln("Error generating voucher: " + err.Error())
							}

							elapsed := time.Since(start)
							log.Printf("Voucher generation took %s", elapsed)

							log.Println("OK\n")
						}
					}

					return nil
				},
			},
			{
				Name: "testreadconfig",
				Action: func(ctx *cli.Context) error {
					configdb := dbs.NewConfigDB(db)
					_, err = configdb.Get()
					if err != nil {
						return fmt.Errorf("Error reading config. " + err.Error())
					}
					return nil
				},
			},
			{
				Name: "testrandomguidpick",
				Action: func(ctx *cli.Context) error {
					configdb := dbs.NewConfigDB(db)
					configInst, err := configdb.Get()
					if err != nil {
						return fmt.Errorf("Error reading config. " + err.Error())
					}

					randomBatch := configInst.SeededGuids.GetTestBatch(500)

					x := randomBatch[fdoshared.StRSA2048]

					x.GetRandomSelection(10)
					return nil
				},
			},
			{
				Name: "testrandid",
				Action: func(ctx *cli.Context) error {
					var randGuids fdoshared.FdoGuidList

					for i := 0; i < 2500; i++ {
						randGuids = append(randGuids, fdoshared.NewFdoGuid())
					}

					for i := 0; i < 2500; i++ {
						randBatch := randGuids.GetRandomBatch(150)
						log.Println(len(randBatch))
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
			{
				Name: "testVoucherRS256",
				Action: func(ctx *cli.Context) error {

					for i := 0; i < 100; i++ {
						log.Println(fdoshared.Conf_NewRandomSgTypeExcept(fdoshared.StSECP256R1))
					}

					return nil
				},
			},
			{
				Name: "testRandomBufferFuzzing",
				Action: func(ctx *cli.Context) error {
					log.Println(hex.EncodeToString(fdoshared.Conf_RandomCborBufferFuzzing(make([]byte, 32))))

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
