package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
)

type VoucherDB struct {
	db     *badger.DB
	prefix []byte
}

func NewVoucherDB(db *badger.DB) *VoucherDB {
	return &VoucherDB{
		db:     db,
		prefix: []byte("voucher-"),
	}
}

func (h VoucherDB) getEntryID(guid fdoshared.FdoGuid) []byte {
	return append(h.prefix, guid[:]...)
}

func (h *VoucherDB) Save(voucherDBEntry fdoshared.VoucherDBEntry) error {
	voucherDBBytes, err := fdoshared.CborCust.Marshal(voucherDBEntry)
	if err != nil {
		return errors.New("Failed to marshal voucher. " + err.Error())
	}

	ovHeader, err := voucherDBEntry.Voucher.GetOVHeader()
	if err != nil {
		return errors.New("Failed to get voucher header. " + err.Error())
	}

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(h.getEntryID(ovHeader.OVGuid), voucherDBBytes)
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating voucherDB entry instance. " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving voucherDB entry. " + err.Error())
	}

	return nil
}

func (h *VoucherDB) Get(deviceGuid fdoshared.FdoGuid) (*fdoshared.VoucherDBEntry, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(h.getEntryID(deviceGuid))
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The voucher entry for GUID(%s) does not exist", hex.EncodeToString(deviceGuid[:]))
	} else if err != nil {
		return nil, errors.New("Failed locating voucher entry. " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading voucherdb entry value. " + err.Error())
	}

	var voucherDBEInst fdoshared.VoucherDBEntry

	err = fdoshared.CborCust.Unmarshal(itemBytes, &voucherDBEInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding voucherdb entry " + err.Error())
	}

	return &voucherDBEInst, nil
}

func (h *VoucherDB) List() ([]fdoshared.FdoGuid, error) {
	var result []fdoshared.FdoGuid = []fdoshared.FdoGuid{}

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	// Create an iterator to iterate over all key-value pairs
	it := dbtxn.NewIterator(badger.DefaultIteratorOptions)
	defer it.Close()

	// Iterate over all key-value pairs and add the keys to the list
	for it.Seek(h.prefix); it.ValidForPrefix(h.prefix); it.Next() {
		item := it.Item()
		keyBytes := item.KeyCopy(nil)
		if len(keyBytes) != 16 {
			return nil, errors.New("invalid voucherdb entry key length")
		}

		var guid fdoshared.FdoGuid
		guid.FromBytes(keyBytes[:])

		result = append(result, guid)
	}

	return result, nil
}
