package main

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api"
	fdodeviceimplementation "github.com/fido-alliance/iot-fdo-conformance-tools/core/device"
	fdodocommon "github.com/fido-alliance/iot-fdo-conformance-tools/core/device/common"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/device/to1"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/device/to2"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do"
	fdodo "github.com/fido-alliance/iot-fdo-conformance-tools/core/do"
	dodbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/do/to0"
	fdorv "github.com/fido-alliance/iot-fdo-conformance-tools/core/rv"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	testcomdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"

	"github.com/joho/godotenv"

	"github.com/dgraph-io/badger/v4"
	"github.com/urfave/cli/v2"
)

const DEFAULT_PORT = 8080
const BADGER_LOCATION = "./badger.local.db"

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
	options := badger.DefaultOptions(BADGER_LOCATION)
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

func loadEnvCtx() context.Context {
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

	defaultUrl := fmt.Sprintf("http://localhost:%d", selectedPort)

	ctx = context.WithValue(ctx, fdoshared.CFG_ENV_PORT, selectedPort)

	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_DEV_ENV, fdoshared.CFG_ENV_PROD, false)

	// For interop testing
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_URL, "", false)
	iopEnabled := ctx.Value(fdoshared.CFG_ENV_INTEROP_DASHBOARD_URL).(string) != ""

	ctx = context.WithValue(ctx, fdoshared.CFG_ENV_INTEROP_ENABLED, iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_FDO_SERVICE_URL, defaultUrl, iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_RV_AUTHZ, "", iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DASHBOARD_DO_AUTHZ, "", iopEnabled)
	ctx = TryEnvAndSaveToCtx(ctx, fdoshared.CFG_ENV_INTEROP_DO_TOKEN_MAPPING, "", iopEnabled)

	return ctx
}

// Enable SHA1 for x509
// https://go.dev/doc/go1.18#sha1
func enforceSha1GoDebug() {
	godebug := os.Getenv("GODEBUG")
	if godebug != "" {
		godebug += ","
	}
	godebug += "x509sha1=1"
	os.Setenv("GODEBUG", godebug)
}

func checkAndSeed(db *badger.DB) error {
	time.Sleep(4 * time.Second)

	devbasedb := dbs.NewDeviceBaseDB(db)
	configdb := dbs.NewConfigDB(db)

	_, err := configdb.Get()
	if err != nil {
		log.Println("---------- NOTE ----------")
		log.Println("\nPlease wait while tools pre-generate testing private keys. This may take up to five minutes...")
		log.Println("---------- NOTE ----------")
		return PreSeed(configdb, devbasedb)
	} else {
		log.Println("Database already seeded. Skipping...")
	}

	return nil
}

func checkFrontendExists() bool {
	_, err := os.Stat("./frontend")
	return !os.IsNotExist(err)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file. " + err.Error())
	}

	cliapp := &cli.App{
		EnableBashCompletion: true,
		Compiled:             time.Now(),
		Name:                 "IoT Fido Device Onboarding Conformance Test Tools",
		Version:              "v0.7.0",
		Authors: []*cli.Author{
			{
				Name:  "Yuriy Ackermann",
				Email: "ackermann.yuriy@gmail.com",
			},
		},
		Copyright: "(c) 2022-2024 FIDO Alliance, Inc",
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Starts conformance server",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force server to start without checking for frontend folder",
					},
				},
				Action: func(c *cli.Context) error {
					force := c.Bool("force")

					// Enable SHA1 for x509
					enforceSha1GoDebug()

					db := InitBadgerDB()
					defer db.Close()

					seedCheck := checkAndSeed(db)
					if seedCheck != nil {
						return seedCheck
					}

					if !checkFrontendExists() && !force {
						return fmt.Errorf("./frontend folder not found")
					}

					ctx := loadEnvCtx()

					// Setup FDO listeners
					fdodo.SetupServer(db, ctx)
					fdorv.SetupServer(db, ctx)
					api.SetupServer(db, ctx)

					selectedPort := ctx.Value(fdoshared.CFG_ENV_PORT).(int)
					log.Printf("Starting server at port %d... \n. http://localhost:%d", selectedPort, selectedPort)

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
					db := InitBadgerDB()
					defer db.Close()

					return checkAndSeed(db)
				},
			},
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
					log.Println("RVINFO: ", header.OVRvInfo)

					return nil
				},
			},
			{
				Name: "test_devmod",
				Action: func(c *cli.Context) error {
					devmodhex := "8301016d6669646f5f616c6c69616e6365"
					devmodbytes, _ := hex.DecodeString(devmodhex)

					var devModVal []interface{}
					err := fdoshared.CborCust.Unmarshal(devmodbytes, &devModVal)
					if err != nil {
						log.Println(err)
					}

					_, ok := devModVal[0].(uint64)
					if !ok {
						return fmt.Errorf("invalid SIM_DEVMOD_MODULES. First element must be uint")
					}

					dval, ok := devModVal[2].(string)
					if !ok {
						return fmt.Errorf("invalid SIM_DEVMOD_MODULES. First element must be uint")
					}

					log.Println(dval)
					return nil
				},
			},
			{
				Name: "generate_rvinfo",
				Action: func(c *cli.Context) error {
					rvInfo, err := fdoshared.UrlsToRendezvousInfo([]string{
						"http://165.227.240.155:80",   // FIDO
						"http://20.228.111.63:8080",   // Intel
						"http://103.147.123.161:7040", // VinCSS
						"http://44.210.118.60:8040/",  // Dell
					})
					if err != nil {
						log.Panicln(err)
					}

					rvinfoBytes, _ := fdoshared.CborCust.Marshal(rvInfo)
					log.Println("HTTP IP Only", hex.EncodeToString(rvinfoBytes))

					// HTTPS + HTTP IP Only
					rvInfo, err = fdoshared.UrlsToRendezvousInfo([]string{
						"http://165.227.240.155:80",  // FIDO
						"https://172.67.150.203:443", // FIDO
						"https://104.21.0.92:443",    // FIDO

						"http://20.228.111.63:8080", // Intel

						"http://103.147.123.161:7040",  // VinCSS
						"https://103.147.123.161:7040", // VinCSS

						"http://44.210.118.60:8040/",  // Dell
						"https://44.210.118.60:8041/", // Dell
					})
					if err != nil {
						log.Panicln(err)
					}

					rvinfoBytes, _ = fdoshared.CborCust.Marshal(rvInfo)
					log.Println("HTTP + HTTPS IP Only", hex.EncodeToString(rvinfoBytes))

					// HTTPS + HTTP IP Only
					rvInfo, err = fdoshared.UrlsToRendezvousInfo([]string{
						"http://165.227.240.155:80",   // FIDO
						"https://172.67.150.203:443",  // FIDO
						"https://104.21.0.92:443",     // FIDO
						"https://rv.fdo.tools:443",    // FIDO
						"http://http.rv.fdo.tools:80", // FIDO

						"http://20.228.111.63:8080",                      // Intel
						"http://bmo-rrp.westus.cloudapp.azure.com:8080/", // Intel

						"http://103.147.123.161:7040",    // VinCSS
						"https://103.147.123.161:7040",   // VinCSS
						"http://vincss-fdo-rv.fido2.vn",  // VinCSS
						"https://vincss-fdo-rv.fido2.vn", // VinCSS

						"http://44.210.118.60:8040/",  // Dell
						"https://44.210.118.60:8041/", // Dell
					})
					if err != nil {
						log.Panicln(err)
					}

					rvinfoBytes, _ = fdoshared.CborCust.Marshal(rvInfo)
					log.Println("HTTP + HTTPS + DNS", hex.EncodeToString(rvinfoBytes))

					return nil
				},
			},
			{
				Name: "load_test_vouchers",
				Action: func(c *cli.Context) error {
					db := InitBadgerDB()
					defer db.Close()

					if err := do.LoadLocalVouchers(dodbs.NewVoucherDB(db)); err != nil {
						return fmt.Errorf("error loading test vouchers. %s", err.Error())
					}

					return nil
				},
			},
			{
				Name:        "iop",
				Description: "Interop and virtual device emmulation",
				Usage:       "vdevice [cmd]",
				Subcommands: []*cli.Command{
					{
						Name:  "generate",
						Usage: "Generate virtual device credential and voucher",
						Action: func(c *cli.Context) error {
							enforceSha1GoDebug()
							deviceSgType := fdoshared.RandomDeviceSgType()
							credbase, err := fdoshared.NewWawDeviceCredential(deviceSgType)
							if err != nil {
								log.Panicf("Error generating cred base. %s", err.Error())
							}

							rvInfo, err := fdoshared.UrlsToRendezvousInfo([]string{
								"http://165.227.240.155:80",   // FIDO
								"http://20.228.111.63:8080",   // Intel
								"http://103.147.123.161:7040", // VinCSS
								"http://44.210.118.60:8040/",  // Dell
							})
							if err != nil {
								log.Panicln(err)
							}

							// rvinfob, err := fdoshared.CborCust.Marshal(rvInfo)

							// print("RVINFO: ", hex.EncodeToString(rvinfob))

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
							enforceSha1GoDebug()
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

							rvdns := to1dPayload.To1dRV[0].RVDNS
							rvipd := to1dPayload.To1dRV[0].RVIP
							rvport := to1dPayload.To1dRV[0].RVPort

							resultString := ""
							if rvdns != nil {
								resultString = resultString + fmt.Sprintf(" DNS: %s", *rvdns)
							}

							if rvipd != nil {
								resultString = resultString + fmt.Sprintf(" IP: %s", rvipd.String())
							}

							resultString = resultString + fmt.Sprintf(" Port: %d", rvport)

							log.Println("Success", resultString)

							return nil
						},
					},
					{
						Name:      "to2",
						Usage:     "Execute TO exchange with RV server",
						UsageText: "[FDO RV Server URL] [Path to DI file]",
						Action: func(c *cli.Context) error {
							enforceSha1GoDebug()
							if c.Args().Len() != 2 {
								log.Println("Missing URL or Filename")
								return nil
							}

							ctx := loadEnvCtx()

							url := c.Args().Get(0)
							filepath := c.Args().Get(1)

							wawcred, err := TryReadingWawDIFile(filepath)
							if err != nil {
								return err
							}

							log.Println("Starting HelloDevice60")
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
							var osSims []fdoshared.ServiceInfoKV = fdoshared.GetDeviceOSSims()

							var deviceSims fdoshared.SIMS
							deviceSims = append(deviceSims, osSims...)

							deviceSims = append(deviceSims, fdoshared.ServiceInfoKV{
								ServiceInfoKey: fdoshared.SIM_DEVMOD_NUMMODULES,
								ServiceInfoVal: fdoshared.UintToCborBytes(1),
							})

							deviceSims = append(deviceSims, fdoshared.ServiceInfoKV{
								ServiceInfoKey: fdoshared.SIM_DEVMOD_MODULES,
								ServiceInfoVal: fdoshared.SimsListToBytes(fdoshared.SIM_IDS{
									fdoshared.IOPLOGGER_SIM_NAME,
								}),
							})

							var ownerSims fdoshared.SIMS // TODO

							for i, deviceSim := range deviceSims {
								log.Println("Sending DeviceServiceInfo68 for sim " + deviceSim.ServiceInfoKey)
								log.Println(hex.EncodeToString(deviceSim.ServiceInfoVal))
								_, _, err := to2inst.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
									ServiceInfo: []fdoshared.ServiceInfoKV{
										deviceSim,
									},
									IsMoreServiceInfo: i+1 <= len(deviceSims),
								}, testcom.NULL_TEST)
								if err != nil {
									log.Println(err)
									return nil
								}
							}

							for {
								ownerSim, _, err := to2inst.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
									ServiceInfo:       []fdoshared.ServiceInfoKV{},
									IsMoreServiceInfo: false,
								}, testcom.NULL_TEST)
								if err != nil {
									log.Println(err)
									return nil
								}

								ownerSims = append(ownerSims, ownerSim.ServiceInfo...)

								for _, ownerSim := range ownerSims {
									log.Println("Receiving OwnerSim DeviceServiceInfo68: " + ownerSim.ServiceInfoKey)
								}

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
								authzval, ok := ownerSims.GetSim(fdoshared.IOPLOGGER_SIM)
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
					{
						Name:      "do_load_vouchers",
						Usage:     "Loads vouchers into DO DB from a folder",
						UsageText: "[Path to vouchers folder]",
						Action: func(c *cli.Context) error {
							if c.Args().Len() != 1 {
								return fmt.Errorf("missing folder path")
							}

							folderPath := c.Args().Get(0)

							// VoucherDB
							db := InitBadgerDB()
							defer db.Close()
							doVoucherDB := dodbs.NewVoucherDB(db)

							// Getting file list
							files, err := os.ReadDir(folderPath)
							if err != nil {
								return err
							}

							if len(files) == 0 {
								return fmt.Errorf("no files found in folder")
							}

							for _, file := range files {
								if !file.IsDir() && filepath.Ext(file.Name()) == ".pem" {
									filePath := filepath.Join(folderPath, file.Name())
									fileBytes, err := os.ReadFile(filePath)

									if err != nil {
										return fmt.Errorf("error reading file \"%s\". %s ", folderPath, err.Error())
									}

									if len(fileBytes) == 0 {
										return fmt.Errorf("error reading file \"%s\". The file is empty", folderPath)
									}

									vandk, err := fdodocommon.DecodePemVoucherAndKey(string(fileBytes))
									if err != nil {
										return fmt.Errorf("error decoding voucher. %s", err.Error())
									}

									vheader, err := vandk.Voucher.GetOVHeader()
									if err != nil {
										return fmt.Errorf("error decoding voucher header. %s", err.Error())
									}

									err = doVoucherDB.Save(*vandk)
									if err != nil {
										return fmt.Errorf("error saving voucher. %s", err.Error())
									}

									log.Println("Saved voucher for " + vheader.OVGuid.GetFormatted())
								}
							}

							return nil
						},
					},
					{
						Name:      "rv_push_vouchers",
						Usage:     "Pushes vouchers to the specified RV",
						UsageText: "[RV URL]",
						Action: func(c *cli.Context) error {
							if c.Args().Len() != 1 {
								return fmt.Errorf("missing folder path")
							}

							rvUrl := c.Args().Get(0)

							ctx := loadEnvCtx()

							// VoucherDB
							db := InitBadgerDB()
							defer db.Close()
							doVoucherDB := dodbs.NewVoucherDB(db)

							voucherList, err := doVoucherDB.List()
							if err != nil {
								return fmt.Errorf("error listing vouchers. %s", err.Error())
							}

							for _, voucherGuid := range voucherList {
								log.Println("Doing voucherGuid " + voucherGuid.GetFormatted())
								vandk, err := doVoucherDB.Get(voucherGuid)
								if err != nil {
									return fmt.Errorf("error getting voucher. %s", err.Error())
								}

								to0 := to0.NewTo0Requestor(fdoshared.SRVEntry{
									SrvURL: rvUrl,
								}, *vandk, ctx)

								helloAck21, _, err := to0.Hello20(testcom.NULL_TEST)
								if err != nil {
									log.Printf("Error running Hello20. %s", err.Error())
									return nil
								}

								_, _, err = to0.OwnerSign22(helloAck21.NonceTO0Sign, testcom.NULL_TEST)
								if err != nil {
									log.Printf("Error running OwnerSign22. %s", err.Error())
									return nil
								}

								log.Println("Success TO0 " + voucherGuid.GetFormatted())
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
