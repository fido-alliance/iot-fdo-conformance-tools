package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgraph-io/badger/v4"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	listenertestsdeps "github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/listener"
	"github.com/fxamacker/cbor/v2"
)

type ListenerTestDB struct {
	db               *badger.DB
	prefix           []byte
	mapperGuidPrefix []byte
	ttl              int
}

func NewListenerTestDB(db *badger.DB) *ListenerTestDB {
	return &ListenerTestDB{
		db:               db,
		prefix:           []byte("lstdb-"),
		mapperGuidPrefix: []byte("lstdb-guid-map-"),
		ttl:              60 * 60 * 24 * 183, //6months storage
	}
}

func (h *ListenerTestDB) getEntryId(entryUuid []byte) []byte {
	return append(h.prefix, entryUuid...)
}

func (h *ListenerTestDB) getMappingEntryId(guid fdoshared.FdoGuid) []byte {
	return append(h.mapperGuidPrefix, guid[:]...)
}

func (h *ListenerTestDB) Save(reqListener listenertestsdeps.RequestListenerInst) error {
	structBytes, err := cbor.Marshal(reqListener)
	if err != nil {
		return errors.New("Failed to marshal listener entry." + err.Error())
	}

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(h.getEntryId(reqListener.Uuid), structBytes).WithTTL(time.Second * time.Duration(h.ttl))
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating listener db entry instance." + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving listener entry." + err.Error())
	}

	h.SaveMapping(reqListener.Guid, reqListener.Uuid)
	if err != nil {
		return errors.New("Failed saving listener entry guid mapping." + err.Error())
	}

	return nil
}

func (h *ListenerTestDB) Update(reqListener *listenertestsdeps.RequestListenerInst) error {
	structBytes, err := cbor.Marshal(reqListener)
	if err != nil {
		return errors.New("Failed to marshal listener entry." + err.Error())
	}

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(h.getEntryId(reqListener.Uuid), structBytes).WithTTL(time.Second * time.Duration(h.ttl))
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating rvte db entry instance." + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving rvte entry." + err.Error())
	}

	return nil
}

func (h *ListenerTestDB) Get(entryUuid []byte) (*listenertestsdeps.RequestListenerInst, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(h.getEntryId(entryUuid))
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The rvte entry with id %s does not exist", hex.EncodeToString(h.getEntryId(entryUuid)))
	} else if err != nil {
		return nil, errors.New("Failed locating rvte entry." + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading rvte entry value." + err.Error())
	}

	var reqListInst listenertestsdeps.RequestListenerInst
	err = cbor.Unmarshal(itemBytes, &reqListInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding rvte entry value." + err.Error())
	}

	return &reqListInst, nil
}

func (h *ListenerTestDB) DeleteMapping(guid fdoshared.FdoGuid) error {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	err := dbtxn.Delete(h.getMappingEntryId(guid))
	if err != nil {
		return errors.New("Failed initialise delete mapping entry." + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to delete guid mapping." + err.Error())
	}

	return nil
}

func (h *ListenerTestDB) DeleteEntry(entryUuid []byte) error {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	err := dbtxn.Delete(h.getEntryId(entryUuid))
	if err != nil {
		return errors.New("Failed initialise delete listener entry." + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to delete listener entry." + err.Error())
	}

	return nil
}

func (h *ListenerTestDB) Delete(entryUuid []byte) error {
	entry, err := h.Get(entryUuid)
	if err != nil {
		return errors.New("Failed initialise delete listener entry. " + err.Error())
	}

	err = h.DeleteMapping(entry.Guid)
	if err != nil {
		return err
	}

	err = h.DeleteEntry(entryUuid)
	if err != nil {
		return err
	}

	return nil
}

func (h *ListenerTestDB) ResetDB() error {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	iterTxn := dbtxn.NewIterator(badger.IteratorOptions{})
	defer iterTxn.Close()
	for iterTxn.Rewind(); iterTxn.ValidForPrefix(h.prefix) || iterTxn.ValidForPrefix(h.mapperGuidPrefix); iterTxn.Next() {
		item := iterTxn.Item()
		k := item.Key()

		log.Println("Deleting... " + hex.EncodeToString(k))

		err := dbtxn.Delete(k)
		if err != nil {
			log.Println("Error creating delete mapping... " + hex.EncodeToString(k))
		}

		err = dbtxn.Commit()
		if err != nil {
			log.Println("Failed to commit delete mapping... " + hex.EncodeToString(k))
		}

	}

	return nil
}

/* ---- Test mgmt menthods ----- */

func (h *ListenerTestDB) GetMany(entriesIds [][]byte) (*[]listenertestsdeps.RequestListenerInst, error) {
	var listenerEntries []listenertestsdeps.RequestListenerInst

	for _, entryUuid := range entriesIds {
		listenerEntry, err := h.Get(entryUuid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(entryUuid), err.Error())
		}

		listenerEntries = append(listenerEntries, *listenerEntry)
	}

	return &listenerEntries, nil
}

func (h *ListenerTestDB) RemoveTestRun(toProtocol fdoshared.FdoToProtocol, testInstId []byte, testRunId string) error {
	testInst, err := h.Get(testInstId)
	if err != nil {
		return fmt.Errorf("%s test entry can not be found. %s", hex.EncodeToString(testInstId), err.Error())
	}

	var chosenReqListRunner listenertestsdeps.RequestListenerRunnerInst
	switch toProtocol {
	case fdoshared.To0:
		chosenReqListRunner = testInst.To0
	case fdoshared.To1:
		chosenReqListRunner = testInst.To1
	case fdoshared.To2:
		chosenReqListRunner = testInst.To2
	default:
		return fmt.Errorf("Unknown FDO protocol %d", toProtocol)
	}

	err = chosenReqListRunner.RemoveTestRun(testRunId)
	if err != nil {
		return err
	}

	switch toProtocol {
	case fdoshared.To0:
		testInst.To0 = chosenReqListRunner
	case fdoshared.To1:
		testInst.To1 = chosenReqListRunner
	case fdoshared.To2:
		testInst.To2 = chosenReqListRunner
	}

	err = h.Save(*testInst)
	if err != nil {
		log.Printf("%s error saving test entry. %s", hex.EncodeToString(testInstId), err.Error())
		return err
	}

	return nil
}

func (h *ListenerTestDB) SaveMapping(guid fdoshared.FdoGuid, uuid []byte) error {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(h.getMappingEntryId(guid), uuid)
	err := dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating listener db mapping entry instance." + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving listener mapping entry." + err.Error())
	}

	return nil
}

func (h *ListenerTestDB) GetMappingEntry(guid fdoshared.FdoGuid) ([]byte, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(h.getMappingEntryId(guid))
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The mapping entry with id %s does not exist", hex.EncodeToString(h.getMappingEntryId(guid)))
	} else if err != nil {
		return nil, errors.New("Failed locating mapping entry." + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading mapping entry value." + err.Error())
	}

	return itemBytes, nil
}

func (h *ListenerTestDB) GetEntryByFdoGuid(guid fdoshared.FdoGuid) (*listenertestsdeps.RequestListenerInst, error) {
	entryUuid, err := h.GetMappingEntry(guid)
	if err != nil {
		return nil, err
	}

	return h.Get(entryUuid)
}
