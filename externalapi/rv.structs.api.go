package externalapi

import (
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

type RVT_Item struct {
	Id  string       `json:"id"`
	Url string       `json:"url"`
	To0 RVT_InstInfo `json:"to0"`
	To1 RVT_InstInfo `json:"to1"`
}

type RVT_ListRvts struct {
	RVTItems []RVT_Item       `json:"entries"`
	Status   FdoConfApiStatus `json:"status"`
}

type RVT_RequestInfo struct {
	Id        string `json:"id"`
	TestRunId string `json:"testRunId,omitempty"`
}
