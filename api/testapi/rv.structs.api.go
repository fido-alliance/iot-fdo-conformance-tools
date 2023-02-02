package testapi

import (
	"github.com/WebauthnWorks/fdo-fido-conformance-server/externalapi/commonapi"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	reqtestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/request"
)

type RVT_CreateTestCase struct {
	Url string `json:"url"`
}

type RVT_InstInfo struct {
	Id         string                        `json:"id"`
	Runs       []reqtestsdeps.RequestTestRun `json:"runs"`
	InProgress bool                          `json:"inprogress"`
	Protocol   fdoshared.FdoToProtocol       `json:"protocol"`
}

func (h *RVT_InstInfo) IsPassing() bool {
	if len(h.Runs) == 0 || h.InProgress {
		return false
	}

	return h.Runs[0].PassingAllTests()
}

type RVT_Item struct {
	Id             string       `json:"id"`
	Url            string       `json:"url"`
	To0            RVT_InstInfo `json:"to0"`
	To1            RVT_InstInfo `json:"to1"`
	SuccessPassing bool         `json:"success"`
}

func (h *RVT_Item) CheckIsPassing() {
	h.SuccessPassing = h.To0.IsPassing() && h.To1.IsPassing()
}

type RVT_ListRvts struct {
	RVTItems []RVT_Item                 `json:"entries"`
	Status   commonapi.FdoConfApiStatus `json:"status"`
}

type RVT_RequestInfo struct {
	Id        string `json:"id"`
	TestRunId string `json:"testRunId,omitempty"`
}
