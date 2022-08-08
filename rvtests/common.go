package rvtests

import (
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type RVTestID string

const (
	FIDO_RVT_31_BAD_ENCODING RVTestID = "FIDO_RVT_20_BAD_ENCODING"
)

type RVTestState struct {
	_ struct{} `cbor:",toarray"`
}

type RVTestMap map[RVTestID]RVTestState

type RVTReporter struct {
}

func (h *RVTReporter) Report(testID RVTestID) {

}

type RendezvousServerTestDBEntry struct {
	_           struct{} `cbor:",toarray"`
	ID          []byte
	URL         string
	VouchersIds []fdoshared.FdoGuid
	TestsPassed RVTestMap
}

func New(url string) RendezvousServerTestDBEntry {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RendezvousServerTestDBEntry{
		ID:  uuidBytes,
		URL: url,
	}
}
