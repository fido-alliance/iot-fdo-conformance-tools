package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type DeviceBaseDB struct {
	db     *badger.DB
	prefix []byte
}

func NewDeviceBaseDB(db *badger.DB) *DeviceBaseDB {
	return &DeviceBaseDB{
		db:     db,
		prefix: []byte("devbase-"),
	}
}

func (h *DeviceBaseDB) Save(deviceBaseDB fdoshared.WawDeviceCredBase) error {
	rvteBytes, err := cbor.Marshal(deviceBaseDB)
	if err != nil {
		return errors.New("Failed to marshal DeviceBase. The error is: " + err.Error())
	}

	storageId := append(h.prefix, deviceBaseDB.FdoGuid[:]...)

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

func (h *DeviceBaseDB) Get(guid fdoshared.FdoGuid) (*fdoshared.WawDeviceCredBase, error) {
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

	var devBase fdoshared.WawDeviceCredBase
	err = cbor.Unmarshal(itemBytes, &devBase)
	if err != nil {
		return nil, errors.New("Failed cbor decoding DevBase entry value. The error is: " + err.Error())
	}

	return &devBase, nil
}

func (h *DeviceBaseDB) GetVANDV(guid fdoshared.FdoGuid, testid testcom.FDOTestID) (*fdodeviceimplementation.DeviceCredAndVoucher, error) {
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

	var devBase fdoshared.WawDeviceCredBase
	err = cbor.Unmarshal(itemBytes, &devBase)
	if err != nil {
		return nil, errors.New("Failed cbor decoding DevBase entry value. The error is: " + err.Error())
	}

	return fdodeviceimplementation.NewVirtualDeviceAndVoucher(devBase, testid)
}

func (h *DeviceBaseDB) GetMany(guids []fdoshared.FdoGuid) (*[]fdoshared.WawDeviceCredBase, error) {
	var devBaseList []fdoshared.WawDeviceCredBase

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		devBaseList = append(devBaseList, *rvt)
	}

	return &devBaseList, nil
}

func (h *DeviceBaseDB) GetGuids(guids []fdoshared.FdoGuid) (*[]fdoshared.WawDeviceCredBase, error) {
	var devBaseList []fdoshared.WawDeviceCredBase

	for _, guid := range guids {
		rvt, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining rvt for id %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		devBaseList = append(devBaseList, *rvt)
	}

	return &devBaseList, nil
}
