package main

import (
	"errors"
	"time"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type HelloDeviceDB struct {
	db *badger.DB
}

func NewOwnerSignDB(db *badger.DB) HelloDeviceDB {
	return HelloDeviceDB{
		db: db,
	}
}

func (h *HelloDeviceDB) Save(sessionId fdoshared.FdoGuid, helloDevice fdoshared.HelloDevice60, ttlSec uint32) error {
	helloDeviceBytes, err := cbor.Marshal(helloDevice)
	if err != nil {
		return errors.New("Failed to marshal ownerSign. The error is: " + err.Error())
	}

	ownerSignStorageId := append([]byte("to1osstorage-"), sessionId[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(ownerSignStorageId, helloDeviceBytes).WithTTL(time.Second * time.Duration(ttlSec)) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating session db entry instance. The error is: " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving session entry. The error is: " + err.Error())
	}

	return nil
}

func (h *HelloDeviceDB) Get(sessionId SessionEntry) (*fdoshared.HelloDevice60, error) {
	ownerSignStorageId := append([]byte("to2osstorage-"), sessionId[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(ownerSignStorageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var helloDeviceInst fdoshared.HelloDevice60
	err = cbor.Unmarshal(itemBytes, &helloDeviceInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &helloDeviceInst, nil
}
