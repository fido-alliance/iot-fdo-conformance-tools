package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type GenTestVoucherDB struct {
	db *badger.DB
}

var gtvdbpref []byte = []byte("gtvoucher-")

func NewGenTestVoucherDB(db *badger.DB) GenTestVoucherDB {
	return GenTestVoucherDB{
		db: db,
	}
}

func (h *GenTestVoucherDB) Save(voucherEntry fdoshared.VoucherDBEntry) error {
	voucherEntryBytes, err := cbor.Marshal(voucherEntry)
	if err != nil {
		return errors.New("Failed to marshal voucher entry. The error is: " + err.Error())
	}

	ovHeader, err := voucherEntry.Voucher.GetOVHeader()
	if err != nil {
		return errors.New("Failed to marshal voucher entry. " + err.Error())
	}
	rvteStorageId := append(gtvdbpref, ovHeader.OVGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(rvteStorageId, voucherEntryBytes).WithTTL(time.Second * time.Duration(RVT_TTLS)) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating rvte db entry instance. The error is: " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving rvte entry. The error is: " + err.Error())
	}

	return nil
}

func (h *GenTestVoucherDB) Get(fdoguid fdoshared.FdoGuid) (*fdoshared.VoucherDBEntry, error) {
	gtvStorageId := append(gtvdbpref, fdoguid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(gtvStorageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The gtv entry with id %s does not exist", hex.EncodeToString(gtvStorageId))
	} else if err != nil {
		return nil, errors.New("Failed locating gtv entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading gtv entry value. The error is: " + err.Error())
	}

	var gtvEInst fdoshared.VoucherDBEntry
	err = cbor.Unmarshal(itemBytes, &gtvEInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding gtv entry value. The error is: " + err.Error())
	}

	return &gtvEInst, nil
}
