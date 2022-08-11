package rvtdeps

import (
	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/google/uuid"
)

type RendezvousServerTestDBEntry struct {
	_              struct{} `cbor:",toarray"`
	ID             []byte
	URL            string
	VDIs           []fdodeviceimplementation.VDANDV
	InProgress     bool
	CurrentTestRun RVTestRun
	TestsHistory   []RVTestRun
}

func NewRVDBTestEntry(url string) RendezvousServerTestDBEntry {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RendezvousServerTestDBEntry{
		ID:  uuidBytes,
		URL: url,
	}
}
