package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	fdodocommon "github.com/WebauthnWorks/fdo-device-implementation/common"
	"github.com/WebauthnWorks/fdo-device-implementation/to1"
	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	fdorv "github.com/WebauthnWorks/fdo-rv"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	testcomdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"

	"github.com/WebauthnWorks/fdo-shared/testcom"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli/v2"
)

const PORT = 8080

func TryReadingWawDIFile(filepath string) (*fdoshared.WawDeviceCredential, error) {
	fileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Error reading file \"%s\". %s ", filepath, err.Error())
	}

	if len(fileBytes) == 0 {
		return nil, fmt.Errorf("Error reading file \"%s\". The file is empty.", filepath)
	}

	wawdicredBlock, _ := pem.Decode(fileBytes)
	if wawdicredBlock == nil {
		return nil, fmt.Errorf("%s: Could not find voucher PEM data!", filepath)
	}

	if wawdicredBlock.Type != fdoshared.CREDENTIAL_PEM_TYPE {
		return nil, fmt.Errorf("%s: Failed to decode PEM voucher. Unexpected type: %s", filepath, wawdicredBlock.Type)
	}

	var wawdicred fdoshared.WawDeviceCredential
	err = cbor.Unmarshal(wawdicredBlock.Bytes, &wawdicred)
	if err != nil {
		return nil, fmt.Errorf("%s: Error unmarshaling WawDeviceCredential: %s", filepath, err.Error())
	}

	return &wawdicred, nil
}

func InitBadgerDB() *badger.DB {
	options := badger.DefaultOptions("./badger.local.db")
	options.Logger = nil

	db, err := badger.Open(options)
	if err != nil {
		log.Panicln("Error opening Badger DB. " + err.Error())
	}

	return db
}

func main() {
	cliapp := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Starts conformance server",
				Action: func(c *cli.Context) error {
					db := InitBadgerDB()
					defer db.Close()

					ctx := context.Background()
					ctx = context.WithValue(ctx, fdoshared.CFG_RESULTS_API_KEY, RESULT_SUBMISSION_API_KEY)
					ctx = context.WithValue(ctx, fdoshared.CFG_MODE, TOOLS_MODE)

					// Setup FDO listeners
					fdodo.SetupServer(db)
					fdorv.SetupServer(db)
					externalapi.SetupServer(db, ctx)

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
					db := InitBadgerDB()
					defer db.Close()

					devbasedb := dbs.NewDeviceBaseDB(db)
					configdb := dbs.NewConfigDB(db)

					return PreSeed(configdb, devbasedb)
				},
			},
			{
				Name:        "vdevice",
				Description: "Virtual device emulation",
				Usage:       "vdevice [cmd]",
				Subcommands: []*cli.Command{
					{
						Name:  "generate",
						Usage: "Generate virtual device credential and voucher",
						Action: func(c *cli.Context) error {
							credbase, err := fdoshared.NewWawDeviceCredBase(fdoshared.HASH_HMAC_SHA256, fdoshared.StRSA2048)
							if err != nil {
								log.Panicf("Error generating cred base. %s", err.Error())
							}

							err = fdodeviceimplementation.GenerateAndSaveDeviceCredAndVoucher(*credbase, testcom.NULL_TEST)
							if err != nil {
								log.Panicf("Error saving voucher base. %s", err.Error())
							}

							return nil
						},
					},
					{
						Name:      "to1",
						Usage:     "Generate test credentials",
						UsageText: "[FDO Server URL]",
						Action: func(c *cli.Context) error {
							if c.Args().Len() != 2 {
								log.Println("Missing URL or Filename")
								return nil
							}

							url := c.Args().Get(0)
							filepath := c.Args().Get(1)

							wawcred, err := TryReadingWawDIFile(filepath)
							if err != nil {
								return err
							}

							to1inst := to1.NewTo1Requestor(fdodocommon.SRVEntry{
								SrvURL: url,
							}, *wawcred)

							helloRvAck31, _, err := to1inst.HelloRV30(testcom.NULL_TEST)
							if err != nil {
								log.Printf("Error running HelloRV30. %s", err.Error())
								return nil
							}

							_, _, err = to1inst.ProveToRV32(*helloRvAck31, testcom.NULL_TEST)
							if err != nil {
								log.Printf("Error running ProveToRV32. %s", err.Error())
								return nil
							}

							return nil
						},
					},
				},
			},
			{
				Name:        "reset",
				Description: "Reset methods",
				Usage:       "reset [cmd]",
				Subcommands: []*cli.Command{
					{
						Name: "users",
						Action: func(ctx *cli.Context) error {
							db := InitBadgerDB()
							defer db.Close()

							userDB := dbs.NewUserTestDB(db)

							return userDB.ResetUsers()
						},
					},
					{
						Name: "listenerdb",
						Action: func(ctx *cli.Context) error {
							db := InitBadgerDB()
							defer db.Close()

							listenerDB := testcomdbs.NewListenerTestDB(db)

							return listenerDB.ResetDB()
						},
					},
				},
			},
		},
	}

	err := cliapp.Run(os.Args)
	if err != nil {
		log.Fatalf("Error executing binary. %s", err.Error())
	}
}
