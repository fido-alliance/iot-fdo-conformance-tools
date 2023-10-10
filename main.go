package main

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fido-alliance/fdo-fido-conformance-server/api"
	fdodeviceimplementation "github.com/fido-alliance/fdo-fido-conformance-server/core/device"
	fdodocommon "github.com/fido-alliance/fdo-fido-conformance-server/core/device/common"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/to1"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/device/to2"
	fdodo "github.com/fido-alliance/fdo-fido-conformance-server/core/do"
	fdorv "github.com/fido-alliance/fdo-fido-conformance-server/core/rv"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
	testcomdbs "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/dbs"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
	"github.com/joho/godotenv"

	"github.com/dgraph-io/badger/v4"
	"github.com/urfave/cli/v2"
)

const DEFAULT_PORT = 8080

func TryReadingWawDIFile(filepath string) (*fdoshared.WawDeviceCredential, error) {
	fileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading file \"%s\". %s ", filepath, err.Error())
	}

	if len(fileBytes) == 0 {
		return nil, fmt.Errorf("error reading file \"%s\". The file is empty", filepath)
	}

	wawdicredBlock, _ := pem.Decode(fileBytes)
	if wawdicredBlock == nil {
		return nil, fmt.Errorf("%s: Could not find voucher PEM data", filepath)
	}

	if wawdicredBlock.Type != fdoshared.CREDENTIAL_PEM_TYPE {
		return nil, fmt.Errorf("%s: Failed to decode PEM voucher. Unexpected type: %s", filepath, wawdicredBlock.Type)
	}

	var wawdicred fdoshared.WawDeviceCredential
	err = fdoshared.CborCust.Unmarshal(wawdicredBlock.Bytes, &wawdicred)
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

func TryEnvAndSaveToCtx(ctx context.Context, envvar fdoshared.CONFIG_ENTRY, defaultValue string, required bool) context.Context {
	resultEnvValue := os.Getenv(strings.ToUpper(string(envvar)))
	if resultEnvValue == "" && required {
		log.Panicf("Missing required environment variable %s", envvar)
	} else if resultEnvValue == "" {
		resultEnvValue = defaultValue
	}

	return context.WithValue(ctx, envvar, resultEnvValue)
}

func loadEnvToCtx() context.Context {
	ctx := context.Background()

	// PORT
	selectedPort := DEFAULT_PORT
	envPortString := os.Getenv(strings.ToUpper(string(fdoshared.CFG_ENV_PORT)))

	if envPortString != "" {
		envPort, err := strconv.Atoi(envPortString)
		if err != nil {
			log.Fatalf("Error converting port to integer: %v", err)
		}

		if envPort != 0 {
			selectedPort = envPort
		}
	}
	ctx = context.WithValue(ctx, fdoshared.CFG_ENV_PORT, selectedPort)

	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_MODE, fdoshared.CFG_MODE_ONPREM, false)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_DEV_ENV, fdoshared.CFG_ENV_PROD, false)

	onlineMandate := ctx.Value(fdoshared.CFG_ENV_MODE).(string) == fdoshared.CFG_MODE_ONLINE
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_API_KEY_RESULTS, "", onlineMandate)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_API_BUILDS_URL, "", onlineMandate)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_FDO_SERVICE_URL, "", onlineMandate)

	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_NOTIFY_SERVICE_HOST, "", onlineMandate)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_NOTIFY_SERVICE_SECRET, "", onlineMandate)

	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GITHUB_CLIENTID, "", false)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GITHUB_CLIENTSECRET, "", false)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GITHUB_REDIRECTURL, "", false)

	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GOOGLE_CLIENTID, "", false)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GOOGLE_CLIENTSECRET, "", false)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_GOOGLE_REDIRECTURL, "", false)

	// TODO: Add Microsoft OAuth2

	// For interop testing
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_URL, "", false)
	iopEnabled := ctx.Value(fdoshared.CFG_ENV_INTEROP_DASHBOARD_URL).(string) != ""

	ctx = context.WithValue(ctx, fdoshared.CFG_ENV_INTEROP_ENABLED, iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_RV_AUTHZ, "", iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_DO_AUTHZ, "", iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_DEVICE_AUTHZ, "", iopEnabled)

	return ctx
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file. " + err.Error())
	}

	cliapp := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Starts conformance server",
				Action: func(c *cli.Context) error {
					db := InitBadgerDB()
					defer db.Close()

					ctx := loadEnvToCtx()

					// Setup FDO listeners
					fdodo.SetupServer(db, ctx)
					fdorv.SetupServer(db, ctx)
					api.SetupServer(db, ctx)

					selectedPort := ctx.Value(fdoshared.CFG_ENV_PORT).(int)
					log.Printf("Starting server at port %d... \n", selectedPort)

					err = http.ListenAndServe(fmt.Sprintf(":%d", selectedPort), nil)
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
					log.Println("\nPlease wait while tools pre-generate testing private keys. This may take up to five minutes...")
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
			{
				Name: "decode_voucher",
				Action: func(c *cli.Context) error {
					if c.Args().Len() != 1 {
						log.Println("Missing URL or Filename. Expected: [FDO RV Server URL] [Path to DI file]")
						return nil
					}

					filepath := c.Args().Get(0)

					fileBytes, err := os.ReadFile(filepath)
					if err != nil {
						return fmt.Errorf("error reading file \"%s\". %s ", filepath, err.Error())
					}

					if len(fileBytes) == 0 {
						return fmt.Errorf("error reading file \"%s\". The file is empty", filepath)
					}

					vandk, err := fdodocommon.DecodePemVoucherAndKey(string(fileBytes))
					if err != nil {
						return fmt.Errorf("error decoding voucher. %s", err.Error())
					}

					voucher := vandk.Voucher

					header, err := voucher.GetOVHeader()
					if err != nil {
						return fmt.Errorf("error decoding voucher. %s", err.Error())
					}

					log.Println("GUID: " + header.OVGuid.GetFormatted())

					return nil
				},
			},
				Name:        "vdevice",
				Description: "Virtual device emulation",
				Usage:       "vdevice [cmd]",
				Subcommands: []*cli.Command{
					{
						Name:  "generate",
						Usage: "Generate virtual device credential and voucher",
						Action: func(c *cli.Context) error {
							credbase, err := fdoshared.NewWawDeviceCredBase(fdoshared.HASH_HMAC_SHA256, fdoshared.StSECP256R1)
							if err != nil {
								log.Panicf("Error generating cred base. %s", err.Error())
							}

							rvInfo, err := fdoshared.UrlsToRendezvousInstrList([]string{
							})
							if err != nil {
								log.Panicln(err)
							}

							voucherSgType := fdoshared.RandomSgType()
							err = fdodeviceimplementation.GenerateAndSaveDeviceCredAndVoucher(*credbase, voucherSgType, rvInfo, testcom.NULL_TEST)
							if err != nil {
								log.Panicf(err.Error())
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
								log.Println("Missing URL or Filename. Expected: [FDO RV Server URL] [Path to DI file]")
								return nil
							}

							url := c.Args().Get(0)
							filepath := c.Args().Get(1)

							wawcred, err := TryReadingWawDIFile(filepath)
							if err != nil {
								return err
							}

							to1inst := to1.NewTo1Requestor(fdoshared.SRVEntry{
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
							err = fdoshared.CborCust.Unmarshal(to1d.Payload, &to1dPayload)
							if err != nil {
								return fmt.Errorf("error decoding TO1D payload! %s", err.Error())
							}

							log.Println(to1dPayload.To1dRV)

							return nil
						},
					},
					{
						Name:      "to2",
						Usage:     "Execute TO exchange with RV server",
						UsageText: "[FDO RV Server URL] [Path to DI file]",
						Action: func(c *cli.Context) error {
							if c.Args().Len() != 2 {
								log.Println("Missing URL or Filename")
								return nil
							}

							ctx := loadEnvToCtx()

							url := c.Args().Get(0)
							filepath := c.Args().Get(1)

							wawcred, err := TryReadingWawDIFile(filepath)
							if err != nil {
								return err
							}

							to2inst := to2.NewTo2Requestor(fdoshared.SRVEntry{
								SrvURL: url,
							}, *wawcred, fdoshared.KEX_ECDH256, fdoshared.CIPHER_A128GCM)

							to2proveOvhdrPayload, _, err := to2inst.HelloDevice60(testcom.NULL_TEST)
							if err != nil {
								log.Printf("Error running HelloDevice60. %s", err.Error())
								return nil
							}

							// 62
							var ovEntries []fdoshared.CoseSignature
							for i := 0; i < int(to2proveOvhdrPayload.NumOVEntries); i++ {
								log.Printf("Requesting GetOVNextEntry62 for entry %d \n", i)
								nextEntry, _, err := to2inst.GetOVNextEntry62(uint8(i), testcom.NULL_TEST)
								if err != nil {
									log.Println(err.Error())
									return nil
								}

								if nextEntry.OVEntryNum != uint8(i) {
									log.Printf("Server retured wrong entry. Expected %d. Got %d", i, nextEntry.OVEntryNum)
									return nil
								}

								ovEntries = append(ovEntries, nextEntry.OVEntry)
							}

							ovEntriesS := fdoshared.OVEntryArray(ovEntries)
							err = ovEntriesS.VerifyEntries(to2proveOvhdrPayload.OVHeader, to2proveOvhdrPayload.HMac)
							if err != nil {
								log.Println(err)
								return nil
							}

							lastOvEntry := ovEntries[len(ovEntries)-1]
							loePubKey, _ := lastOvEntry.GetOVEntryPubKey()

							err = to2inst.ProveOVHdr61PubKey.Equal(loePubKey)
							if err != nil {
								log.Println(err)
								return nil
							}

							//64
							log.Println("Starting ProveDevice64")
							_, _, err = to2inst.ProveDevice64(testcom.NULL_TEST)
							if err != nil {
								log.Println(err)
								return nil
							}

							//66
							log.Println("Starting DeviceServiceInfoReady66")
							_, _, err = to2inst.DeviceServiceInfoReady66(testcom.NULL_TEST)
							if err != nil {
								log.Println(err)
								return nil
							}

							//68
							var deviceSims []fdoshared.ServiceInfoKV = []fdoshared.ServiceInfoKV{
								{
									ServiceInfoKey: "device:test1",
									ServiceInfoVal: []byte("1234"),
								},
								{
									ServiceInfoKey: "device:test2",
									ServiceInfoVal: []byte("1234"),
								},
								{
									ServiceInfoKey: "device:test3",
									ServiceInfoVal: []byte("1234"),
								},
								{
									ServiceInfoKey: "device:test4",
									ServiceInfoVal: []byte("1234"),
								},
								{
									ServiceInfoKey: "device:test5",
									ServiceInfoVal: []byte("1234"),
								},
								{
									ServiceInfoKey: "device:test6",
									ServiceInfoVal: []byte("1234"),
								},
							}

							var ownerSims []fdoshared.ServiceInfoKV // TODO

							for i, deviceSim := range deviceSims {
								log.Println("Sending DeviceServiceInfo68 for sim " + deviceSim.ServiceInfoKey)
								_, _, err := to2inst.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
									ServiceInfo:       &deviceSim,
									IsMoreServiceInfo: i+1 <= len(deviceSims),
								}, testcom.NULL_TEST)
								if err != nil {
									log.Println(err)
									return nil
								}
							}

							for {
								ownerSim, _, err := to2inst.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
									ServiceInfo:       nil,
									IsMoreServiceInfo: false,
								}, testcom.NULL_TEST)
								if err != nil {
									log.Println(err)
									return nil
								}

								log.Println("Receiving OwnerSim DeviceServiceInfo68 " + ownerSim.ServiceInfo.ServiceInfoKey)

								ownerSims = append(ownerSims, *ownerSim.ServiceInfo)
								if ownerSim.IsDone {
									break
								}
							}

							log.Println("Starting Done70")
							_, _, err = to2inst.Done70(testcom.NULL_TEST)
							if err != nil {
								log.Println(err)
								return nil
							}
							log.Println("Success To2")

							// FDO Interop

							iopEnabled := ctx.Value(fdoshared.CFG_ENV_INTEROP_ENABLED).(bool)
							if iopEnabled {
								authzval, ok := fdoshared.GetSim(ownerSims, fdoshared.IOPLOGGER_SIM)
								if !ok {
									log.Println("IOP logger not found in owner sims")
									return nil
								}

								log.Println("Submitting IOP logger event")
								err = fdoshared.SubmitIopLoggerEvent(ctx, to2inst.Credential.DCGuid, fdoshared.To2, to2inst.NonceTO2SetupDv64, string(authzval))
								if err != nil {
									log.Println(err)
									return nil
								}
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

	err = cliapp.Run(os.Args)
	if err != nil {
		log.Fatalf("Error executing binary. %s", err.Error())
	}
}
