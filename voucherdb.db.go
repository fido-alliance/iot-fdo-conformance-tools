package main

import "github.com/WebauthnWorks/fdo-do/fdoshared"

// import (
// 	"github.com/WebauthnWorks/fdo-do/fdoshared"
// 	"github.com/dgraph-io/badger/v3"
// )

type VoucherStorageEntry struct {
	Guid       fdoshared.FdoGuid
	Voucher    fdoshared.OwnershipVoucher
	DeviceInfo string
}

// type VoucherStorageDB struct {
// 	db *badger.DB
// }

// func NewVoucherDB(db *badger.DB) SessionDB {
// 	return SessionDB{
// 		db: db,
// 	}
// }

// func (h *SessionDB) RegisterAuthToken(authToken []byte) ([]byte, error) {
// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	entry := badger.NewEntry(authToken, nil).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
// 	err := dbtxn.SetEntry(entry)
// 	if err != nil {
// 		return []byte{}, errors.New("Failed creating session db entry instance. The error is: " + err.Error())
// 	}

// 	dbtxn.Commit()
// 	if err != nil {
// 		return []byte{}, errors.New("Failed saving session entry. The error is: " + err.Error())
// 	}

// 	return []byte(randomEntryId.String()), nil
// }

// func (h *SessionDB) AuthTokenExists(authToken []byte) error {
// 	sessionEntryId := append([]byte("Bearer"), authToken...)

// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	headerIsOk, authHeader, _ := ExtractAuthorizationHeader(w, r, fdoshared.VOUCHER_API)
// 	if !headerIsOk {
// 		RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, fdoshared.TO2_GET_OVNEXTENTRY_62, "Unauthorized. Header token invalid", http.StatusUnauthorized)
// 		return
// 	}

// 	return nil
// }

// func (h *SessionDB) SaveAuthToken(authToken []byte) error {
// 	sessionBytes, err := cbor.Marshal(sessionInst)
// 	if err != nil {
// 		return []byte{}, errors.New("Failed to marshal session. The error is: " + err.Error())
// 	}

// 	randomEntryId, _ := uuid.NewRandom()
// 	sessionEntryId := []byte("session-" + randomEntryId.String())

// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	entry := badger.NewEntry(sessionEntryId, sessionBytes).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
// 	err = dbtxn.SetEntry(entry)
// 	if err != nil {
// 		return []byte{}, errors.New("Failed creating session db entry instance. The error is: " + err.Error())
// 	}

// 	dbtxn.Commit()
// 	if err != nil {
// 		return []byte{}, errors.New("Failed saving session entry. The error is: " + err.Error())
// 	}

// 	return []byte(randomEntryId.String()), nil
// }

// func (h *SessionDB) DeleteVoucher(authToken []byte, voucherGuid []byte) (*VoucherStorageEntry, error) {
// 	sessionEntryId := append([]byte("session-"), entryId...)

// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	item, err := dbtxn.Get(sessionEntryId)
// 	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
// 		return nil, nil
// 	} else if err != nil {
// 		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
// 	}

// 	itemBytes, err := item.ValueCopy(nil)
// 	if err != nil {
// 		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
// 	}

// 	var sessionEntryInst SessionEntry

// 	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
// 	if err != nil {

// 		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
// 	}

// 	return &sessionEntryInst, nil
// }

// func (h *SessionDB) AppendVoucher(entryId []byte) (*SessionEntry, error) {
// 	sessionEntryId := append([]byte("session-"), entryId...)

// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	item, err := dbtxn.Get(sessionEntryId)
// 	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
// 		return nil, nil
// 	} else if err != nil {
// 		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
// 	}

// 	itemBytes, err := item.ValueCopy(nil)
// 	if err != nil {
// 		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
// 	}

// 	var sessionEntryInst SessionEntry

// 	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
// 	if err != nil {

// 		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
// 	}

// 	return &sessionEntryInst, nil
// }

// func (h *SessionDB) GetVouchers(entryId []byte) (*SessionEntry, error) {
// 	sessionEntryId := append([]byte("session-"), entryId...)

// 	dbtxn := h.db.NewTransaction(true)
// 	defer dbtxn.Discard()

// 	item, err := dbtxn.Get(sessionEntryId)
// 	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
// 		return nil, nil
// 	} else if err != nil {
// 		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
// 	}

// 	itemBytes, err := item.ValueCopy(nil)
// 	if err != nil {
// 		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
// 	}

// 	var sessionEntryInst SessionEntry

// 	err = cbor.Unmarshal(itemBytes, &sessionEntryInst)
// 	if err != nil {

// 		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
// 	}

// 	return &sessionEntryInst, nil
// }
