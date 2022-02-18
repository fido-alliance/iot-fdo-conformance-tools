package main

import (
	"errors"
	"time"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type SessionDB struct {
	db *badger.DB
}

func NewSessionDB(db *badger.DB) SessionDB {
	return SessionDB{
		db: db,
	}
}

type SessionEntry struct {
	_        struct{} `cbor:",toarray"`
	Protocol fdoshared.FdoToProtocol

	NonceTO0Sign      []byte
	NonceTO1Proof     []byte
	NonceTO2ProveOV   []byte
	NonceTO2ProveDv61 []byte
	NonceTO2SetupDv   []byte

	NumOVEntries uint8
	NextCmd      fdoshared.FdoCmd

	TO2ProveOVHdrPayload fdoshared.TO2ProveOVHdrPayload
	LastOVEntryNum       uint8
	EASigInfo            fdoshared.SigInfo
	Voucher              fdoshared.OwnershipVoucher
	SessionKey           []byte
	PrivateKey           []byte
	XAKeyExchange        fdoshared.XAKeyExchange

	KexSuiteName    string
	CipherSuiteName string
	Guid            fdoshared.FdoGuid
	ShSeDO          []byte

	MaxDeviceServiceInfoSz                  uint16
	ServiceInfoMsgNo                        uint8
	OwnerServiceInfoIsMoreServiceInfoIsTrue bool
}

func (h *SessionDB) NewSessionEntry(sessionInst SessionEntry) ([]byte, error) {
	sessionBytes, err := cbor.Marshal(sessionInst)
	if err != nil {
		return []byte{}, errors.New("Failed to marshal session. The error is: " + err.Error())
	}

	randomEntryId, _ := uuid.NewRandom()
	sessionEntryId := []byte("session-" + randomEntryId.String())

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(sessionEntryId, sessionBytes).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return []byte{}, errors.New("Failed creating session db entry instance. The error is: " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return []byte{}, errors.New("Failed saving session entry. The error is: " + err.Error())
	}

	return []byte(randomEntryId.String()), nil
}

func (h *SessionDB) UpdateSessionEntry(entryId []byte, sessionInst SessionEntry) error {
	sessionEntryId := append([]byte("session-"), entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	sessionInstBytes, err := cbor.Marshal(sessionInst)
	if err != nil {
		return errors.New("Failed to marshal session. The error is: " + err.Error())
	}

	err = dbtxn.Set(sessionEntryId, sessionInstBytes)
	if err != nil {
		return errors.New("Failed to create saving inst. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to save session. The error is: " + err.Error())
	}

	return nil
}

func (h *SessionDB) GetSessionEntry(entryId []byte) (*SessionEntry, error) {
	sessionEntryId := append([]byte("session-"), entryId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(sessionEntryId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var sessionEntryInst SessionEntry

	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
	if err != nil {

		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &sessionEntryInst, nil
}
