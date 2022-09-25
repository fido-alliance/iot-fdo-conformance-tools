package externalapi

import (
	reqtestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

type DOT_CreateTestCase struct {
	Url string `json:"url"`
}

type DOT_InstInfo struct {
	Id         string                        `json:"id"`
	Runs       []reqtestsdeps.RequestTestRun `json:"runs"`
	InProgress bool                          `json:"inprogress"`
	Protocol   fdoshared.FdoToProtocol       `json:"protocol"`
}

type DOT_Item struct {
	Id  string       `json:"id"`
	Url string       `json:"url"`
	To2 DOT_InstInfo `json:"to2"`
}

type DOT_ListTestEntries struct {
	TestEntries []DOT_Item       `json:"entries"`
	Status      FdoConfApiStatus `json:"status"`
}

type DOT_RequestInfo struct {
	Id        string `json:"id"`
	TestRunId string `json:"testRunId,omitempty"`
}
