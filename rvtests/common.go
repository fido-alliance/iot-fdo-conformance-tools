package rvtests

import (
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
)

type RVTestMap map[testcom.FDOTestID]testcom.FDOTestState

type RVTestRun struct {
	_         struct{} `cbor:",toarray"`
	Timestamp int64
	Tests     RVTestMap
}

func NewRVTestRun() RVTestRun {
	newRVTestRun := RVTestRun{
		Timestamp: time.Now().Unix(),
		Tests:     RVTestMap{},
	}

	return newRVTestRun
}
