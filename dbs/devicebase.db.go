package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/dgraph-io/badger/v4"
	fdodeviceimplementation "github.com/fido-alliance/fdo-fido-conformance-server/core/device"
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

type DeviceBaseDB struct {
	db     *badger.DB
	prefix []byte
}

func NewDeviceBaseDB(db *badger.DB) *DeviceBaseDB {
	return &DeviceBaseDB{
		db:     db,
		prefix: []byte("devbasecreds-"),
	}
}

func (h *DeviceBaseDB) Save(deviceBaseDB fdoshared.WawDeviceCredential) error {
	rvteBytes, err := fdoshared.CborCust.Marshal(deviceBaseDB)
	if err != nil {
		return errors.New("Failed to marshal DeviceBase. The error is: " + err.Error())
	}

	storageId := append(h.prefix, deviceBaseDB.DCGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(storageId, rvteBytes)
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

func (h *DeviceBaseDB) Get(guid fdoshared.FdoGuid) (*fdoshared.WawDeviceCredential, error) {
	storageId := append(h.prefix, guid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(storageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The devCred entry with id %s does not exist", hex.EncodeToString(guid[:]))
	} else if err != nil {
		return nil, errors.New("Failed locating devCred entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading devCred entry value. The error is: " + err.Error())
	}

	var devCred fdoshared.WawDeviceCredential
	err = fdoshared.CborCust.Unmarshal(itemBytes, &devCred)
	if err != nil {
		return nil, errors.New("Failed cbor decoding devCred entry value. The error is: " + err.Error())
	}

	return &devCred, nil
}

func (h *DeviceBaseDB) GetVANDV(guid fdoshared.FdoGuid, testid testcom.FDOTestID) (*fdoshared.DeviceCredAndVoucher, error) {
	storageId := append(h.prefix, guid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(storageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The DevBase entry with id %s does not exist", hex.EncodeToString(guid[:]))
	} else if err != nil {
		return nil, errors.New("Failed locating DevBase entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading DevBase entry value. The error is: " + err.Error())
	}

	var devCred fdoshared.WawDeviceCredential
	err = fdoshared.CborCust.Unmarshal(itemBytes, &devCred)
	if err != nil {
		return nil, errors.New("Failed cbor decoding DevBase entry value. The error is: " + err.Error())
	}

	// TODO
	rvInfo, err := fdoshared.UrlsToRendezvousInstrList([]string{
		"https://localhost:8043",
	})
	if err != nil {
		log.Panicln(err)
	}

	randomSgType := fdoshared.RandomSgType()
	return fdodeviceimplementation.NewVirtualDeviceAndVoucher(devCred, randomSgType, rvInfo, testid)
}

func (h *DeviceBaseDB) GetMany(guids []fdoshared.FdoGuid) (*[]fdoshared.WawDeviceCredential, error) {
	var devCredsList []fdoshared.WawDeviceCredential

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		devCredsList = append(devCredsList, *rvt)
	}

	return &devCredsList, nil
}

func (h *DeviceBaseDB) GetGuids(guids []fdoshared.FdoGuid) (*[]fdoshared.WawDeviceCredential, error) {
	var devCredsList []fdoshared.WawDeviceCredential

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		devCredsList = append(devCredsList, *rvt)
	}

	return &devCredsList, nil
}
