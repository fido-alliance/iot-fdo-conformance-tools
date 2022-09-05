package req_tests_deps

import (
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type RequestTestInstDBEntry struct {
	_              struct{} `cbor:",toarray"`
	Uuid           []byte
	URL            string
	FdoSeedIDs     fdoshared.FdoSeedIDs
	InProgress     bool
	CurrentTestRun RVTestRun
	TestsHistory   []RVTestRun
}

func NewServerTestEntry(url string) RequestTestInstDBEntry {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RequestTestInstDBEntry{
		Uuid:         uuidBytes,
		URL:          url,
		TestsHistory: make([]RVTestRun, 0),
	}
}
