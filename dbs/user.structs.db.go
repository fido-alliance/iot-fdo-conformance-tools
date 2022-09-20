package dbs

import (
	"bytes"

	"github.com/dgraph-io/badger/v3"
	"github.com/google/uuid"
)

type UserTestDB struct {
	db     *badger.DB
	prefix []byte
}

type DOTestInst struct {
	_    struct{} `cbor:",toarray"`
	Uuid []byte
	Url  string
	To2  []byte
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

type UserTestDBEntry struct {
	_            struct{} `cbor:",toarray"`
	Username     string
	PasswordHash []byte
	Name         string
	Company      string
	Phone        string
	RVTestInsts  []RVTestInst
	DOTestInsts  []DOTestInst
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
	for _, rvt := range h.DOTestInsts {
		if bytes.Equal(rvt.To2, dotid) {
			return true
		}
	}

	return false
}
