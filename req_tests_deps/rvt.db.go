package reqtestsdeps

import (
	"fmt"
	"time"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/google/uuid"
)

type TestVouchers map[testcom.FDOTestID][]fdodeviceimplementation.DeviceCredAndVoucher

func (h *TestVouchers) GetVoucher(testId testcom.FDOTestID) (*fdodeviceimplementation.DeviceCredAndVoucher, error) {
	for k, v := range *h {
		if k == testId {
			randVoucherId := fdoshared.NewRandomInt(0, len(v)-1)

			return &v[randVoucherId], nil
		}
	}

	return nil, fmt.Errorf("No vouchers found for the id %s", testId)
}

type RequestTestInst struct {
	_              struct{} `cbor:",toarray"`
	Uuid           []byte
	URL            string
	Protocol       fdoshared.FdoToProtocol
	FdoSeedIDs     fdoshared.FdoSeedIDs
	InProgress     bool
	CurrentTestRun RequestTestRun
	TestsHistory   []RequestTestRun
	TestVouchers   TestVouchers
}

func NewRequestTestInst(url string, protocol fdoshared.FdoToProtocol) RequestTestInst {
	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()

	return RequestTestInst{
		Uuid:         uuidBytes,
		URL:          url,
		TestsHistory: make([]RequestTestRun, 0),
		Protocol:     protocol,
		TestVouchers: make(TestVouchers),
	}
}

type RequestTestResultMap map[testcom.FDOTestID]testcom.FDOTestState

type RequestTestRun struct {
	_         struct{}                `cbor:",toarray"`
	Uuid      string                  `json:"uuid"`
	Timestamp int64                   `json:"timestamp"`
	Tests     RequestTestResultMap    `json:"tests"`
	Protocol  fdoshared.FdoToProtocol `json:"protocol"`
}

func NewRVTestRun(protocol fdoshared.FdoToProtocol) RequestTestRun {
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
