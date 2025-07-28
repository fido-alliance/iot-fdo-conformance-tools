package testapi

import (
	"github.com/fido-alliance/iot-fdo-conformance-tools/api/commonapi"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	reqtestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/request"
)

type DOT_CreateTestCase struct {
	Url     string `json:"url"`
	PrivKey string `json:"priv_key"`
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
	TestEntries []DOT_Item                 `json:"entries"`
	Status      commonapi.FdoConfApiStatus `json:"status"`
}

type DOT_RequestInfo struct {
	Id        string `json:"id"`
	TestRunId string `json:"testRunId,omitempty"`
}
