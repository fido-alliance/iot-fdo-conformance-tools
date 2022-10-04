package listenertestsdeps

import (
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type ListenerTestRun struct {
	_         struct{}                `cbor:",toarray"`
	Uuid      string                  `json:"uuid"`
	Timestamp int64                   `json:"timestamp"`
	TestRuns  []testcom.FDOTestState  `json:"tests"`
	Protocol  fdoshared.FdoToProtocol `json:"protocol"`
}

func NewListenerTestRun(protocol fdoshared.FdoToProtocol) ListenerTestRun {
	newUuid, _ := uuid.NewRandom()
	uuidStr, _ := newUuid.MarshalText()
	newRVTestRun := ListenerTestRun{
		Uuid:      string(uuidStr),
		Timestamp: time.Now().Unix(),
		TestRuns:  []testcom.FDOTestState{},
		Protocol:  protocol,
	}

	return newRVTestRun
}
