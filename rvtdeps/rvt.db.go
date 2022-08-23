package rvtdeps

import (
	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/google/uuid"
)

type RendezvousServerTestDBEntry struct {
	_              struct{} `cbor:",toarray"`
	Uuid           []byte
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
		Uuid:         uuidBytes,
		URL:          url,
		TestsHistory: make([]RVTestRun, 0),
	}
}
