package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli/v2"
)

const PORT = 8083

func SetupServer(db *badger.DB) {
	to0 := RvTo0{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
	}

	to1 := RvTo1{
		session: &SessionDB{
			db: db,
		},
		ownersignDB: &OwnerSignDB{
			db: db,
		},
	}

	http.HandleFunc("/fdo/101/msg/20", to0.Handle20Hello)
	http.HandleFunc("/fdo/101/msg/22", to0.Handle22OwnerSign)
	http.HandleFunc("/fdo/101/msg/30", to1.Handle30HelloRV)
	http.HandleFunc("/fdo/101/msg/32", to1.Handle32ProveToRV)
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
				Usage: "Starts rv",
				Action: func(c *cli.Context) error {
					SetupServer(db)

					log.Printf("Starting server at port %d... \n", PORT)

					err := http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil)
					if err != nil {
						log.Panicln("Error starting HTTP server. " + err.Error())
					}
					return nil
				},
			},
			// {
			// 	Name:  "gen",
			// 	Usage: "Generates OwnerSign22 payload",
			// 	Action: func(c *cli.Context) error {
			// 		GenPayload22()
			// 		return nil
			// 	},
			// },
		},
	}

	err = cliapp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
