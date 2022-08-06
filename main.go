package main

import (
	"encoding/hex"
	"errors"
	"log"
	"os"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli/v2"
)

type HelloRV30 struct {
	_         struct{} `cbor:",toarray"`
	Guid      []byte
	EASigInfo fdoshared.SigInfo
}

func main() {
	cliapp := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "genvoucher",
				Usage: "Generate new ownership voucher and DI. See _dis and _vouchers",
				Action: func(c *cli.Context) error {
					err := GenerateVoucher(fdoshared.StSECP256R1)

					if err != nil {
						return errors.New("Error generating voucher. " + err.Error())
					}
					return nil
				},
			},
			{
				Name:  "testdecode",
				Usage: "Test decoding",
				Action: func(c *cli.Context) error {
					sourceBytes, _ := hex.DecodeString("82508d62ddb18b404cf58cf5f22cef5c4576822678244920616d206120706f7461746f652120536d6172742c20496f542c20706f7461746f6521")

					var helloRv30 HelloRV30

					err := cbor.Unmarshal(sourceBytes, &helloRv30)

					if err != nil {
						log.Panic("Error decoding source: " + err.Error())
					}

					return nil
				},
			},
			{
				Name:  "testTo1",
				Usage: "",
				Action: func(c *cli.Context) error {
					credential, err := LoadLocalCredentials()
					if err != nil {
						log.Panic(err)
					}

					to1requestor := NewTo1Requestor(SRVEntry{
						SrvURL:      "http://localhost:8083",
						AccessToken: "",
					}, credential)

					helloRVAck31, err := to1requestor.HelloRV30()
					if err != nil {
						log.Panic(err)
					}

					_, err = to1requestor.ProveToRV32(helloRVAck31)
					if err != nil {
						log.Panic(err)
					}
					log.Println("Success To1")

					return nil
				},
			},
			{
				Name:  "testTo2",
				Usage: "",
				Action: func(c *cli.Context) error {
					credential, err := LoadLocalCredentials()
					if err != nil {
						log.Panic(err)
					}

					to2requestor := NewTo2Requestor(SRVEntry{
						SrvURL:      "http://localhost:8080",
						AccessToken: "",
					}, credential, fdoshared.KEX_ECDH256, fdoshared.CIPHER_COSE_AES128_CTR)

					// 60
					log.Println("Starting with ProveOVHdrPayload61")
					ProveOVHdrPayload61, err := to2requestor.HelloDevice60()
					if err != nil {
						log.Panic(err)
					}

					// 62
					var ovEntries []fdoshared.CoseSignature
					for i := 0; i < int(ProveOVHdrPayload61.NumOVEntries); i++ {
						log.Printf("Requesting GetOVNextEntry62 for entry %d \n", i)
						nextEntry, err := to2requestor.GetOVNextEntry62(uint8(i))
						if err != nil {
							log.Panic(err)
						}

						if nextEntry.OVEntryNum != uint8(i) {
							log.Panicf("Server retured wrong entry. Expected %d. Got %d", i, nextEntry.OVEntryNum)
						}

						ovEntries = append(ovEntries, nextEntry.OVEntry)
					}

					ovEntriesS := fdoshared.OVEntryArray(ovEntries)
					err = ovEntriesS.VerifyEntries(ProveOVHdrPayload61.OVHeader, ProveOVHdrPayload61.HMac)
					if err != nil {
						log.Panic(err)
					}

					lastOvEntry := ovEntries[len(ovEntries)-1]
					loePubKey, _ := lastOvEntry.GetOVEntryPubKey()

					err = to2requestor.ProveOVHdr61PubKey.Equals(loePubKey)
					if err != nil {
						log.Panic(err)
					}

					//64
					log.Println("Starting with ProveDevice64")
					_, err = to2requestor.ProveDevice64()
					if err != nil {
						log.Panic(err)
					}

					//66
					log.Println("Starting with DeviceServiceInfoReady66")
					_, err = to2requestor.DeviceServiceInfoReady66()
					if err != nil {
						log.Panic(err)
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
						_, err := to2requestor.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
							ServiceInfo:       &deviceSim,
							IsMoreServiceInfo: i+1 <= len(deviceSims),
						})
						if err != nil {
							log.Panic(err)
						}
					}

					for {
						ownerSim, err := to2requestor.DeviceServiceInfo68(fdoshared.DeviceServiceInfo68{
							ServiceInfo:       nil,
							IsMoreServiceInfo: false,
						})
						if err != nil {
							log.Panic(err)
						}

						log.Println("Receiving OwnerSim DeviceServiceInfo68 " + ownerSim.ServiceInfo.ServiceInfoKey)

						ownerSims = append(ownerSims, *ownerSim.ServiceInfo)

						if ownerSim.IsDone {
							break
						}
					}

					//70
					log.Println("Starting Done70")
					_, err = to2requestor.Done70()
					if err != nil {
						log.Panic(err)
					}

					log.Println("Success To2")

					return nil
				},
			},
		},
	}

	err := cliapp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
