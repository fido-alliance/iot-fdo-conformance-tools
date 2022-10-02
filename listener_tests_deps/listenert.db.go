package listenertestsdeps

import (
	"fmt"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

type FdoImplementationType string

const (
	Device                  FdoImplementationType = "device"
	RendezvousServer        FdoImplementationType = "rv"
	DeviceOnboardingService FdoImplementationType = "do"
)

type RequestListenerRunnerInst struct {
	Protocol      fdoshared.FdoToProtocol `cbor:"protocol,omitempty"`
	LastTestID    testcom.FDOTestID       `cbor:"expectedCmd,omitempty"`
	ExpectedCmd   fdoshared.FdoCmd        `cbor:"expectedCmd,omitempty"`
	CompletedCmds []fdoshared.FdoCmd      `cbor:"completedCmds,omitempty"`

	CurrentTestIndex int                                      `cbor:"currentTestIndex,omitempty"`
	Tests            map[fdoshared.FdoCmd][]testcom.FDOTestID `cbor:"tests,omitempty"`
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

func (h *RequestListenerRunnerInst) CheckExpectedCmd(currentCmd fdoshared.FdoCmd) bool {
	return currentCmd == h.ExpectedCmd
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
	if len(h.TestRunHistory) != 0 {
		h.TestRunHistory = append([]ListenerTestRun{h.CurrentTestRun}, h.TestRunHistory...)
	}

	h.CurrentTestRun = NewListenerTestRun(h.Protocol)
}

func (h *RequestListenerRunnerInst) RemoveTestRun(id string) error {
	var newList []ListenerTestRun = []ListenerTestRun{}

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

func (h *RequestListenerRunnerInst) CompleteCmd(nextCMD fdoshared.FdoCmd) {
	h.CompletedCmds = append(h.CompletedCmds, h.ExpectedCmd)
	h.ExpectedCmd = nextCMD
	h.CurrentTestIndex = 0
}

func (h *RequestListenerRunnerInst) PushFail(errorMsg string) {
	h.CurrentTestRun.TestRun = append(h.CurrentTestRun.TestRun, testcom.NewFailTestState(h.GetLastTestID(), errorMsg))
}

func (h *RequestListenerRunnerInst) PushSuccess() {
	h.CurrentTestRun.TestRun = append(h.CurrentTestRun.TestRun, testcom.NewSuccessTestState(h.GetLastTestID()))
}
