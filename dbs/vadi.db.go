package dbs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
)

type VirtualDeviceTestDB struct {
	db *badger.DB
}

var vdandvpref []byte = []byte("vdanvid-")

func NewVDandVDB(db *badger.DB) VirtualDeviceTestDB {
	return VirtualDeviceTestDB{
		db: db,
	}
}

func (h *VirtualDeviceTestDB) Save(vdandvEntry fdodeviceimplementation.VDANDV) error {
	voucherEntryBytes, err := cbor.Marshal(vdandvEntry)
	if err != nil {
		return errors.New("Failed to marshal vdandv entry. " + err.Error())
	}

	vdandvStorageId := append(vdandvpref, vdandvEntry.WawDeviceCredential.DCGuid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	entry := badger.NewEntry(vdandvStorageId, voucherEntryBytes).WithTTL(time.Second * time.Duration(RVT_TTLS)) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return errors.New("Failed creating vdandv db entry instance. " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed saving vdandv entry. " + err.Error())
	}

	return nil
}

func (h *VirtualDeviceTestDB) Get(fdoguid fdoshared.FdoGuid) (*fdodeviceimplementation.VDANDV, error) {
	vdandvStorageId := append(vdandvpref, fdoguid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(vdandvStorageId)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("The vdandv entry with id %s does not exist", hex.EncodeToString(vdandvStorageId))
	} else if err != nil {
		return nil, errors.New("Failed locating vdandv entry. " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading vdandv entry value. " + err.Error())
	}

	var vdandvInst fdodeviceimplementation.VDANDV
	err = cbor.Unmarshal(itemBytes, &vdandvInst)
	if err != nil {
		return nil, errors.New("Failed cbor decoding vdandv entry value. " + err.Error())
	}

	return &vdandvInst, nil
}

func (h *VirtualDeviceTestDB) GetMany(fdoguids []fdoshared.FdoGuid) (*[]fdodeviceimplementation.VDANDV, error) {
	var vadis []fdodeviceimplementation.VDANDV

	for _, guid := range fdoguids {
		vadi, err := h.Get(guid)
		if err != nil {
			return nil, fmt.Errorf("Error obtaining VDANDV for guid %s. %s \n", hex.EncodeToString(guid[:]), err.Error())
		}

		vadis = append(vadis, *vadi)
	}

	return &vadis, nil
}

func (h *VirtualDeviceTestDB) Delete(fdoguid fdoshared.FdoGuid) error {
	vdandvStorageId := append(vdandvpref, fdoguid[:]...)

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	err := dbtxn.Delete(vdandvStorageId)
	if err != nil {
		return errors.New("Failed to create delete ref. " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to delete inst. " + err.Error())
	}

	return nil
}
