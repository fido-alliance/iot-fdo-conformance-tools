package dbs

import (
	"bytes"

	"github.com/dgraph-io/badger/v3"
	fdoshared "github.com/fido-alliance/fdo-shared"
	"github.com/google/uuid"
)

type UserTestDB struct {
	db     *badger.DB
	prefix []byte
}

type DOTestInst struct {
	_           struct{} `cbor:",toarray"`
	Uuid        []byte
	Url         string
	To2         []byte
	ListenerTo0 []byte
}

func NewDOTestInst(url string, to2 []byte) DOTestInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return DOTestInst{
		Uuid: uuidBytes,
		Url:  url,
		To2:  to2,
	}
}

type RVTestInst struct {
	_    struct{} `cbor:",toarray"`
	Uuid []byte
	Url  string
	To0  []byte
	To1  []byte
}

func NewRVTestInst(url string, to0 []byte, to1 []byte) RVTestInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RVTestInst{
		Uuid: uuidBytes,
		Url:  url,
		To0:  to0,
		To1:  to1,
	}
}

type DeviceTestInst struct {
	_            struct{} `cbor:",toarray"`
	Uuid         []byte
	DeviceGuid   fdoshared.FdoGuid
	Name         string
	ListenerUuid []byte
}

func NewDeviceTestInst(name string, listenerUuid []byte, guid fdoshared.FdoGuid) DeviceTestInst {
	return DeviceTestInst{
		Name:         name,
		DeviceGuid:   guid,
		ListenerUuid: listenerUuid,
	}
}

type AccountStatus string

const (
	AS_Awaiting  AccountStatus = "awaiting"
	AS_Blocked   AccountStatus = "blocked"
	AS_Validated AccountStatus = "validated"
)

type UserTestDBEntry struct {
	_            struct{} `cbor:",toarray"`
	Email        string   `cbor:"email"`
	PasswordHash []byte   `cbor:"password_hash"`
	Name         string   `cbor:"name"`
	Company      string   `cbor:"company"`

	EmailVerified bool          `cbor:"email_verified"`
	Status        AccountStatus `cbor:"account_status"`

	RVTestInsts     []RVTestInst     `cbor:"test_rv"`
	DOTestInsts     []DOTestInst     `cbor:"test_do"`
	DeviceTestInsts []DeviceTestInst `cbor:"test_device"`
}

func (h *UserTestDBEntry) RVT_ContainID(rvtid []byte) bool {
	for _, rvt := range h.RVTestInsts {
		if bytes.Equal(rvt.To0, rvtid) || bytes.Equal(rvt.To1, rvtid) {
			return true
		}
	}

	return false
}

func (h *UserTestDBEntry) DOT_ContainID(dotid []byte) bool {
	for _, dotinst := range h.DOTestInsts {
		if bytes.Equal(dotinst.To2, dotid) || bytes.Equal(dotinst.ListenerTo0, dotid) {
			return true
		}
	}

	return false
}

func (h *UserTestDBEntry) DeviceT_ContainID(id []byte) bool {
	for _, devtinst := range h.DeviceTestInsts {
		if bytes.Equal(devtinst.ListenerUuid, id) {
			return true
		}
	}

	return false
}
