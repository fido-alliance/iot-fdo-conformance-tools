package main

import (
	"errors"
	"time"

	"github.com/WebauthnWorks/fdo-device-implementation/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type VoucherDB struct {
	db *badger.DB
}

func NewVoucherDB(db *badger.DB) VoucherDB {
	return VoucherDB{
		db: db,
	}
}

func (h *SessionDB) Save(guid fdoshared.FdoGuid, voucherDBEntry VoucherDBEntry) error {
	voucherDbEntryBytes, err := cbor.Marshal(voucherDBEntry)
	if err != nil {
		return errors.New("Failed to marshal voucher db entry. The error is: " + err.Error())
	}

	voucherEntryId := append([]byte("voucherdb-"), guid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(voucherEntryId, voucherDbEntryBytes).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating voucher db entry instance. The error is: " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving voucher entry. The error is: " + err.Error())
	}

	return nil
}

func (h *SessionDB) Get(guid fdoshared.FdoGuid) (*VoucherDBEntry, error) {
	voucherEntryId := append([]byte("voucherdb-"), guid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(voucherEntryId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var voucherDBEntryInst VoucherDBEntry
	err = cbor.Unmarshal(itemBytes, &voucherDBEntryInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &voucherDBEntryInst, nil
}
