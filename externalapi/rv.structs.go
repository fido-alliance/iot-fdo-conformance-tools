package externalapi

import (
	"github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
)

type RVT_CreateTestCase struct {
	Url string `json:"url"`
}

type RVT_InstInfo struct {
	Id         string                          `json:"id"`
	Runs       []req_tests_deps.RequestTestRun `json:"runs"`
	InProgress bool                            `json:"inprogress"`
	Protocol   int                             `json:"protocol"`
}

type RVT_Item struct {
	Id  string       `json:"id"`
	Url string       `json:"url"`
	To0 RVT_InstInfo `json:"to0"`
	To1 RVT_InstInfo `json:"to1"`
}

type RVT_ListRvts struct {
	RVTItems []RVT_Item       `json:"rvts"`
	Status   FdoConfApiStatus `json:"status"`
}

type RVT_ExecureReq struct {
	Id string `json:"id"`
}
