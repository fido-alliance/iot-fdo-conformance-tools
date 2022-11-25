package listener

import (
	"fmt"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/WebauthnWorks/fdo-shared/testcom"
)

type FdoImplementationType string

const (
	Device                  FdoImplementationType = "device"
	RendezvousServer        FdoImplementationType = "rv"
	DeviceOnboardingService FdoImplementationType = "do"
)

type RequestListenerRunnerInst struct {
	Protocol      fdoshared.FdoToProtocol `cbor:"protocol,omitempty"`
	LastTestID    testcom.FDOTestID       `cbor:"lastTestID,omitempty"`
	ExpectedCmd   fdoshared.FdoCmd        `cbor:"expectedCmd,omitempty"`
	CompletedCmds []fdoshared.FdoCmd      `cbor:"completedCmds,omitempty"`

	CurrentTestIndex int                                      `cbor:"currentTestIndex,omitempty"`
	Tests            map[fdoshared.FdoCmd][]testcom.FDOTestID `cbor:"tests,omitempty"`
	Running          bool                                     `cbor:"running,omitempty"`
	Completed        bool                                     `cbor:"completed,omitempty"`
	CurrentTestRun   ListenerTestRun                          `cbor:"currentTestRun,omitempty"`
	TestRunHistory   []ListenerTestRun                        `cbor:"testRunHistory,omitempty"`
}

type RequestListenerInst struct {
	Uuid        []byte                    `cbor:"uuid,omitempty"`
	Guid        fdoshared.FdoGuid         `cbor:"guid,omitempty"`
	TestVoucher fdoshared.VoucherDBEntry  `cbor:"testvoucher,omitempty"`
	Type        FdoImplementationType     `cbor:"type,omitempty"`
	To0         RequestListenerRunnerInst `cbor:"to0,omitempty"`
	To1         RequestListenerRunnerInst `cbor:"to1,omitempty"`
	To2         RequestListenerRunnerInst `cbor:"to2,omitempty"`
}

func (h *RequestListenerInst) GetProtocolInst(toProtocol int) (*RequestListenerRunnerInst, error) {
	switch fdoshared.FdoToProtocol(toProtocol) {
	case fdoshared.To0:
		return &h.To0, nil
	case fdoshared.To1:
		return &h.To1, nil
	case fdoshared.To2:
		return &h.To2, nil
	default:
		return nil, fmt.Errorf("Unknown FDO protocol %d", toProtocol)
	}
}

func (h *RequestListenerRunnerInst) CheckExpectedCmd(currentCmd fdoshared.FdoCmd) bool {
	return currentCmd == h.ExpectedCmd
}

func (h *RequestListenerRunnerInst) CheckExpectedCmds(expectedCmds []fdoshared.FdoCmd) bool {
	for _, cmd := range expectedCmds {
		if h.ExpectedCmd == cmd {
			return true
		}
	}

	return false
}

func (h *RequestListenerRunnerInst) CheckCmdTestingIsCompleted(currentCmd fdoshared.FdoCmd) bool {
	for _, completedCmd := range h.CompletedCmds {
		if completedCmd == currentCmd {
			return true
		}
	}

	return false
}

func (h *RequestListenerRunnerInst) StartNewTestRun() {
	if len(h.TestRunHistory) != 0 && h.Running {
		h.TestRunHistory = append([]ListenerTestRun{h.CurrentTestRun}, h.TestRunHistory...)
	}

	h.Running = true
	h.Completed = false

	h.CurrentTestRun = NewListenerTestRun(h.Protocol)
	h.CurrentTestIndex = 0
	h.CompletedCmds = []fdoshared.FdoCmd{}

	switch h.Protocol {
	case fdoshared.To0:
		h.ExpectedCmd = fdoshared.TO0_20_HELLO
	case fdoshared.To1:
		h.ExpectedCmd = fdoshared.TO1_30_HELLO_RV
	case fdoshared.To2:
		h.ExpectedCmd = fdoshared.TO2_60_HELLO_DEVICE
	}
}

func (h *RequestListenerRunnerInst) RemoveTestRun(id string) error {
	var newList []ListenerTestRun = []ListenerTestRun{}

	if h.CurrentTestRun.Uuid == id {
		h.CurrentTestRun = ListenerTestRun{}
		h.Running = false
		return nil
	}

	for _, testRun := range h.TestRunHistory {
		if id != testRun.Uuid {
			newList = append(newList, testRun)
		}
	}

	if len(newList) == len(h.TestRunHistory) {
		return fmt.Errorf("Error removing test run for %s. Not found", id)
	}

	h.TestRunHistory = newList

	return nil
}

func (h *RequestListenerRunnerInst) GetNextTestID() testcom.FDOTestID {
	selectedTestID := h.Tests[h.ExpectedCmd][h.CurrentTestIndex]

	h.LastTestID = selectedTestID
	h.CurrentTestIndex = h.CurrentTestIndex + 1

	return selectedTestID
}

func (h *RequestListenerRunnerInst) GetLastTestID() testcom.FDOTestID {
	return h.LastTestID
}

func (h *RequestListenerRunnerInst) CompleteCmdAndSetNext(nextCMD fdoshared.FdoCmd) {
	h.CompletedCmds = append(h.CompletedCmds, h.ExpectedCmd)
	h.ExpectedCmd = nextCMD
	h.CurrentTestIndex = 0
}

func (h *RequestListenerRunnerInst) CompleteTestRun() {
	h.CompletedCmds = append(h.CompletedCmds, h.ExpectedCmd)
	h.Running = false
	h.Completed = true

	h.CurrentTestRun.Complete()
	h.TestRunHistory = append(h.TestRunHistory, h.CurrentTestRun)
}

func (h *RequestListenerRunnerInst) PushFail(errorMsg string) {
	h.CurrentTestRun.TestRuns = append(h.CurrentTestRun.TestRuns, testcom.NewFailTestState(h.GetLastTestID(), errorMsg))
}

func (h *RequestListenerRunnerInst) PushSuccess() {
	h.CurrentTestRun.TestRuns = append(h.CurrentTestRun.TestRuns, testcom.NewSuccessTestState(h.GetLastTestID()))
}
