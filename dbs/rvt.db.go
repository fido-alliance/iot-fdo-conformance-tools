package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/rvtdeps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type RendezvousServerTestDB struct {
	db *badger.DB
}

var RVT_TTLS int = 60 * 60 * 24 * 183 //6months storage

var rvtdbpref []byte = []byte("rvte-")

func NewRendezvousServerTestDB(db *badger.DB) RendezvousServerTestDB {
	return RendezvousServerTestDB{
		db: db,
	}
}

func (h *RendezvousServerTestDB) Save(rvte rvtdeps.RendezvousServerTestDBEntry) error {
	rvteBytes, err := cbor.Marshal(rvte)
	if err != nil {
		return errors.New("Failed to marshal rvte. The error is: " + err.Error())
	}

	rvteStorageId := append(rvtdbpref, rvte.ID...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(rvteStorageId, rvteBytes).WithTTL(time.Second * time.Duration(RVT_TTLS)) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating rvte db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving rvte entry. The error is: " + err.Error())
	}

	return nil
}

func (h *RendezvousServerTestDB) Update(rvtId []byte, rvte rvtdeps.RendezvousServerTestDBEntry) error {
	rvteBytes, err := cbor.Marshal(rvte)
	if err != nil {
		return errors.New("Failed to marshal rvte. The error is: " + err.Error())
	}

	rvteStorageId := append(rvtdbpref, rvtId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(rvteStorageId, rvteBytes).WithTTL(time.Second * time.Duration(RVT_TTLS)) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating rvte db entry instance. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving rvte entry. The error is: " + err.Error())
	}

	return nil
}

func (h *RendezvousServerTestDB) Get(rvtId []byte) (*rvtdeps.RendezvousServerTestDBEntry, error) {
	rvteStorageId := append(rvtdbpref, rvtId...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(rvteStorageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The rvte entry with id %s does not exist", hex.EncodeToString(rvtId))
	} else if err != nil {
		return nil, errors.New("Failed locating rvte entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading rvte entry value. The error is: " + err.Error())
	}

	var rvteInst rvtdeps.RendezvousServerTestDBEntry
	err = cbor.Unmarshal(itemBytes, &rvteInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding rvte entry value. The error is: " + err.Error())
	}

	return &rvteInst, nil
}

func (h *RendezvousServerTestDB) GetMany(rvtids [][]byte) (*[]rvtdeps.RendezvousServerTestDBEntry, error) {
	var rvts []rvtdeps.RendezvousServerTestDBEntry

	for _, rvtid := range rvtids {
		rvt, err := h.Get(rvtid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(rvtid), err.Error())
		}

		rvts = append(rvts, *rvt)
	}

	return &rvts, nil
}

func (h *RendezvousServerTestDB) StartNewRun(rvid []byte) {
	rvte, err := h.Get(rvid)
	if err != nil {
		log.Printf("%s test entry can not be found.", hex.EncodeToString(rvid))
	}

	newRVTestRun := rvtdeps.NewRVTestRun()

	rvte.InProgress = true
	rvte.CurrentTestRun = newRVTestRun
	rvte.TestsHistory = append([]rvtdeps.RVTestRun{newRVTestRun}, rvte.TestsHistory...)

	err = h.Save(*rvte)
	if err != nil {
		log.Printf("%s error saving test entry.", hex.EncodeToString(rvid))
	}
}

func (h *RendezvousServerTestDB) FinishRun(rvid []byte) {
	rvte, err := h.Get(rvid)
	if err != nil {
		log.Printf("%s test entry can not be found.", hex.EncodeToString(rvid))
	}

	newRVTestRun := rvtdeps.NewRVTestRun()

	rvte.InProgress = false
	rvte.CurrentTestRun = newRVTestRun
	rvte.TestsHistory = append([]rvtdeps.RVTestRun{newRVTestRun}, rvte.TestsHistory...)

	err = h.Save(*rvte)
	if err != nil {
		log.Printf("%s error saving test entry.", hex.EncodeToString(rvid))
	}
}

func (h *RendezvousServerTestDB) ReportTest(rvid []byte, testID testcom.FDOTestID, testResult testcom.FDOTestState) {
	rvte, err := h.Get(rvid)
	if err != nil {
		log.Printf("%s test entry can not be found.", hex.EncodeToString(rvid))
	}

	rvte.CurrentTestRun.Tests[testID] = testResult
	rvte.TestsHistory[0] = rvte.CurrentTestRun

	err = h.Save(*rvte)
	if err != nil {
		log.Printf("%s error saving test entry.", hex.EncodeToString(rvid))
	}
}
