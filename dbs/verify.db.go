package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type VerifyDB struct {
	db     *badger.DB
	prefix []byte
}

func NewVerifyDB(db *badger.DB) *VerifyDB {
	return &VerifyDB{
		db:     db,
		prefix: []byte("verifydb-"),
	}
}

const MAX_VERIFY_TIME time.Duration = 7 * 24 * time.Hour

type VerifyType string

const (
	VT_Email         VerifyType = "email"
	VT_User          VerifyType = "user"
	VT_PasswordReset VerifyType = "password_reset"
)

type VerifyEntry struct {
	_     struct{} `cbor:",toarray"`
	Email string
	Type  VerifyType
}

func (h *VerifyDB) SaveEntry(verifyEntry VerifyEntry) ([]byte, error) {
	vtBytes, err := cbor.Marshal(verifyEntry)
	if err != nil {
		return []byte{}, errors.New("Failed to marshal vt. The error is: " + err.Error())
	}

	randomEntryId, _ := uuid.NewRandom()
	randomEntryIdString := randomEntryId.String()
	vtEntryId := append(h.prefix, []byte(randomEntryIdString)...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(vtEntryId, vtBytes).WithTTL(MAX_VERIFY_TIME)
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return []byte{}, errors.New("Failed creating vt db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return []byte{}, errors.New("Failed saving vt entry. The error is: " + err.Error())
	}

	return []byte(randomEntryId.String()), nil
}

func (h *VerifyDB) GetEntry(entryId []byte) (*VerifyEntry, error) {
	entryDbId := append(h.prefix, entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(entryDbId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The session entry with id %s does not exist", hex.EncodeToString(entryId))
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var sessionEntryInst VerifyEntry
	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &sessionEntryInst, nil
}

func (h *VerifyDB) DeleteEntry(entryId []byte) error {
	entryDbId := append(h.prefix, entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	err := dbtxn.Delete(entryDbId)
	if err != nil {
		return errors.New("Failed initialise delete entry. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to delete session. The error is: " + err.Error())
	}

	return nil
}
