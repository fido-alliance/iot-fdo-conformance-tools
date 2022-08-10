package rvtests

import (
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type RendezvousServerTestDBEntry struct {
	_           struct{} `cbor:",toarray"`
	ID          []byte
	URL         string
	VouchersIds []fdoshared.FdoGuid
	TestsPassed RVTestMap
}

func NewRVDBTestEntry(url string) RendezvousServerTestDBEntry {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RendezvousServerTestDBEntry{
		ID:  uuidBytes,
		URL: url,
	}
}
