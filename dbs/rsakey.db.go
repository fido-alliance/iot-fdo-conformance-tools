package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"

	fdoshared "github.com/WebauthnWorks/fdo-shared"

	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type RsaKeyDB struct {
	db     *badger.DB
	prefix []byte
}

type RsaKeyDBEntry struct {
	_             struct{} `cbor:",toarray"`
	Guid          fdoshared.FdoGuid
	SgType        fdoshared.DeviceSgType
	PublicKey     fdoshared.FdoPublicKey
	PrivateKeyDer []byte
}

func NewRsaKeyDB(db *badger.DB) RsaKeyDB {
	return RsaKeyDB{
		db:     db,
		prefix: []byte("rsakeyentry-"),
	}
}

func (h *RsaKeyDB) Save(rsaKeyDB RsaKeyDBEntry) (fdoshared.FdoGuid, error) {
	newRandomGuid := fdoshared.NewFdoGuid()

	rvteBytes, err := cbor.Marshal(rsaKeyDB)
	if err != nil {
		return newRandomGuid, errors.New("Failed to marshal DeviceBase. The error is: " + err.Error())
	}

	storageId := append(h.prefix, newRandomGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(storageId, rvteBytes)
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return newRandomGuid, errors.New("Failed creating rvte db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return newRandomGuid, errors.New("Failed saving rvte entry. The error is: " + err.Error())
	}

	return newRandomGuid, nil
}

func (h *RsaKeyDB) Get(guid fdoshared.FdoGuid) (*RsaKeyDBEntry, error) {
	storageId := append(h.prefix, guid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(storageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The RsaKeyDBEntry entry with id %s does not exist", hex.EncodeToString(guid[:]))
	} else if err != nil {
		return nil, errors.New("Failed locating RsaKeyDBEntry entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading RsaKeyDBEntry entry value. The error is: " + err.Error())
	}

	var rsaKeyEntry RsaKeyDBEntry
	err = cbor.Unmarshal(itemBytes, &rsaKeyEntry)
	if err != nil {
		return nil, errors.New("Failed cbor decoding RsaKeyDBEntry entry value. The error is: " + err.Error())
	}

	return &rsaKeyEntry, nil
}

func (h *RsaKeyDB) GetMany(guids []fdoshared.FdoGuid) (*[]RsaKeyDBEntry, error) {
	var rsaKeyEntryList []RsaKeyDBEntry

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		rsaKeyEntryList = append(rsaKeyEntryList, *rvt)
	}

	return &rsaKeyEntryList, nil
}

func (h *RsaKeyDB) GetGuids(guids []fdoshared.FdoGuid) (*[]RsaKeyDBEntry, error) {
	var rsaKeyEntryList []RsaKeyDBEntry

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		rsaKeyEntryList = append(rsaKeyEntryList, *rvt)
	}

	return &rsaKeyEntryList, nil
}
