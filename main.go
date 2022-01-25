package main

import (
	"errors"
	"log"
	"os"

	"github.com/WebauthnWorks/fdo-device-implementation/fdoshared"
	"github.com/urfave/cli/v2"
)

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
		},
	}

	err := cliapp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
