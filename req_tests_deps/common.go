package req_tests_deps

import (
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	"github.com/google/uuid"
)

type RVTestMap map[testcom.FDOTestID]testcom.FDOTestState

type RVTestRun struct {
	_         struct{}  `cbor:",toarray"`
	Uuid      string    `json:"uuid"`
	Timestamp int64     `json:"timestamp"`
	Tests     RVTestMap `json:"tests"`
}

func NewRVTestRun() RVTestRun {
	newUuid, _ := uuid.NewRandom()
	uuidStr, _ := newUuid.MarshalText()
	newRVTestRun := RVTestRun{
		Uuid:      string(uuidStr),
		Timestamp: time.Now().Unix(),
		Tests:     RVTestMap{},
	}

	return newRVTestRun
}
