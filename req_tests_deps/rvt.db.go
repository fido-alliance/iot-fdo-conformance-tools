package req_tests_deps

import (
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type RequestTestInst struct {
	_              struct{} `cbor:",toarray"`
	Uuid           []byte
	URL            string
	Protocol       int
	FdoSeedIDs     fdoshared.FdoSeedIDs
	InProgress     bool
	CurrentTestRun RequestTestRun
	TestsHistory   []RequestTestRun
}

func NewRequestTestInst(url string, protocol int) RequestTestInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RequestTestInst{
		Uuid:         uuidBytes,
		URL:          url,
		TestsHistory: make([]RequestTestRun, 0),
		Protocol:     protocol,
	}
}

type RequestTestResultMap map[testcom.FDOTestID]testcom.FDOTestState

type RequestTestRun struct {
	_         struct{}             `cbor:",toarray"`
	Uuid      string               `json:"uuid"`
	Timestamp int64                `json:"timestamp"`
	Tests     RequestTestResultMap `json:"tests"`
	Protocol  int                  `json:"protocol"`
}

func NewRVTestRun(protocol int) RequestTestRun {
	newUuid, _ := uuid.NewRandom()
	uuidStr, _ := newUuid.MarshalText()
	newRVTestRun := RequestTestRun{
		Uuid:      string(uuidStr),
		Timestamp: time.Now().Unix(),
		Tests:     RequestTestResultMap{},
		Protocol:  protocol,
	}

	return newRVTestRun
}
