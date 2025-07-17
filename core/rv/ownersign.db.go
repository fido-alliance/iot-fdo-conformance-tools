package rv

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
)

type OwnerSignDB struct {
	db *badger.DB
}

func NewOwnerSignDB(db *badger.DB) OwnerSignDB {
	return OwnerSignDB{
		db: db,
	}
}

func (h *OwnerSignDB) Save(deviceGuid fdoshared.FdoGuid, ownerSign fdoshared.OwnerSign22, ttlSec uint32) error {
	ownerSignBytes, err := fdoshared.CborCust.Marshal(ownerSign)
	if err != nil {
		return errors.New("Failed to marshal ownerSign. The error is: " + err.Error())
	}

	ownerSignStorageId := append([]byte("to1osstorage-"), deviceGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(ownerSignStorageId, ownerSignBytes).WithTTL(time.Second * time.Duration(ttlSec))
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating session db entry instance. The error is: " + err.Error())
	}

	if err := dbtxn.Commit(); err != nil {
		return errors.New("Failed saving session entry. The error is: " + err.Error())
	}

	return nil
}

func (h *OwnerSignDB) Get(deviceGuid fdoshared.FdoGuid) (*fdoshared.OwnerSign22, error) {
	ownerSignStorageId := append([]byte("to1osstorage-"), deviceGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(ownerSignStorageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The owner sign entry with id %s does not exist", hex.EncodeToString(deviceGuid[:]))
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var ownerSignInst fdoshared.OwnerSign22
	err = fdoshared.CborCust.Unmarshal(itemBytes, &ownerSignInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &ownerSignInst, nil
}
