package dbs

import (
	"errors"
	"fmt"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type ConfigDB struct {
	db     *badger.DB
	prefix []byte
}

func NewConfigDB(db *badger.DB) ConfigDB {
	return ConfigDB{
		db:     db,
		prefix: []byte("config-"),
	}
}

type MainConfig struct {
	_           struct{} `cbor:",toarray"`
	SeededGuids fdoshared.FdoSeedIDs
}

func (h *ConfigDB) Save(mainCfg MainConfig) error {
	payloadBytes, err := cbor.Marshal(mainCfg)
	if err != nil {
		return errors.New("Failed to marshal MainConfig. The error is: " + err.Error())
	}

	storageId := append(h.prefix, []byte("main")...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(storageId, payloadBytes)
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating MainConfig db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving MainConfig entry. The error is: " + err.Error())
	}

	return nil
}

func (h *ConfigDB) Get() (*MainConfig, error) {
	storageId := append(h.prefix, []byte("main")...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(storageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The MainConfig entry with does not exist")
	} else if err != nil {
		return nil, errors.New("Failed locating MainConfig entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading MainConfig entry value. The error is: " + err.Error())
	}

	var mainConfig MainConfig
	err = cbor.Unmarshal(itemBytes, &mainConfig)
	if err != nil {
		return nil, errors.New("Failed cbor decoding MainConfig entry value. The error is: " + err.Error())
	}

	return &mainConfig, nil
}
