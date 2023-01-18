package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	fdodocommon "github.com/WebauthnWorks/fdo-device-implementation/common"
	"github.com/WebauthnWorks/fdo-device-implementation/to1"
	fdodo "github.com/WebauthnWorks/fdo-do"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/tools"
	fdorv "github.com/WebauthnWorks/fdo-rv"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	testcomdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"

	"github.com/WebauthnWorks/fdo-shared/testcom"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli/v2"
)

const DEFAULT_PORT = 8080

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

					selectedPort := DEFAULT_PORT

					apiKeyResult := os.Getenv(strings.ToUpper(string(fdoshared.CFG_API_KEY_RESULTS)))
					if apiKeyResult == "" {
						apiKeyResult = APIKEY_RESULT_SUBMISSION
					}
					apiKeyBuilds := os.Getenv(strings.ToUpper(string(fdoshared.CFG_API_BUILDS_URL)))
					if apiKeyBuilds == "" {
						apiKeyBuilds = APIKEY_BUILDS_URL
					}
					fdoServiceUrl := os.Getenv(strings.ToUpper(string(fdoshared.CFG_FDO_SERVICE_URL)))
					if fdoServiceUrl == "" {
						fdoServiceUrl = FDO_SERVICE_URL
					}
					fdoDevEnvState := os.Getenv(strings.ToUpper(string(tools.CFG_DEV_ENV)))
					if fdoDevEnvState == "" {
						fdoDevEnvState = FDO_DEV_ENV_DEFAULT
					}
					portEnv := os.Getenv(strings.ToUpper(string(tools.CFG_ENV_PORT)))
					if portEnv != "" {
						portEnvNum, err := strconv.ParseInt(portEnv, 10, 0)
						if err != nil {
							log.Panicln("Error error reading port. " + err.Error())
						}

						selectedPort = int(portEnvNum)
					}

					// Github OAuth2
					githubOauth2_clientid := os.Getenv(strings.ToUpper(string(tools.CFG_GITHUB_CLIENTID)))
					if githubOauth2_clientid == "" {
						githubOauth2_clientid = GITHUB_OAUTH2_CLIENTID
					}
					githubOauth2_clientsecret := os.Getenv(strings.ToUpper(string(tools.CFG_GITHUB_CLIENTSECRET)))
					if githubOauth2_clientsecret == "" {
						githubOauth2_clientsecret = GITHUB_OAUTH2_CLIENTISECRET
					}
					githubOauth2_redirecturl := os.Getenv(strings.ToUpper(string(tools.CFG_GITHUB_REDIRECTURL)))
					if githubOauth2_redirecturl == "" {
						githubOauth2_redirecturl = GITHUB_OAUTH2_REDIRECTURL
					}

					ctx := context.Background()
					ctx = context.WithValue(ctx, fdoshared.CFG_API_KEY_RESULTS, apiKeyResult)
					ctx = context.WithValue(ctx, fdoshared.CFG_API_BUILDS_URL, apiKeyBuilds)
					ctx = context.WithValue(ctx, fdoshared.CFG_FDO_SERVICE_URL, fdoServiceUrl)
					ctx = context.WithValue(ctx, fdoshared.CFG_MODE, TOOLS_MODE)
					ctx = context.WithValue(ctx, tools.CFG_DEV_ENV, fdoDevEnvState)

					ctx = context.WithValue(ctx, tools.CFG_GITHUB_CLIENTID, githubOauth2_clientid)
					ctx = context.WithValue(ctx, tools.CFG_GITHUB_CLIENTSECRET, githubOauth2_clientsecret)
					ctx = context.WithValue(ctx, tools.CFG_GITHUB_REDIRECTURL, githubOauth2_redirecturl)

					// Setup FDO listeners
					fdodo.SetupServer(db)
					fdorv.SetupServer(db)
					externalapi.SetupServer(db, ctx)

					log.Printf("Starting server at port %d... \n", selectedPort)

					err := http.ListenAndServe(fmt.Sprintf(":%d", selectedPort), nil)
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
					log.Println("---------- NOTE ----------")
					log.Println("\nPlease wait while tools pre-generate testing private keys. This may take up to five minutes...\n")
					log.Println("---------- NOTE ENDS ----------")

					time.Sleep(4 * time.Second)

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
						Usage:     "Execute TO1 exchange with RV server",
						UsageText: "[FDO RV Server URL] [Path to DI file]",
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

							to1d, _, err := to1inst.ProveToRV32(*helloRvAck31, testcom.NULL_TEST)
							if err != nil {
								log.Printf("Error running ProveToRV32. %s", err.Error())
								return nil
							}

							var to1dPayload fdoshared.To1dBlobPayload
							err = cbor.Unmarshal(to1d.Payload, &to1dPayload)
							if err != nil {
								return fmt.Errorf("Error decoding TO1D payload! %s", err.Error())
							}

							log.Println(to1dPayload.To1dRV)

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
