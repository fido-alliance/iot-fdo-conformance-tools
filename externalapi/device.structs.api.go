package externalapi

import (
	listenertestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/listener"
)

type Device_CreateTestCase struct {
	Name                 string `json:"name"`
	VoucherAndPrivateKey string `json:"voucher"`
}

type Device_Item struct {
	Id   string                              `json:"id"`
	Name string                              `json:"name"`
	Guid string                              `json:"guid"`
	To1  []listenertestsdeps.ListenerTestRun `json:"to1"`
	To2  []listenertestsdeps.ListenerTestRun `json:"to2"`
}

type Device_ListRuns struct {
	DeviceItems []Device_Item    `json:"entries"`
	Status      FdoConfApiStatus `json:"status"`
}

type Device_RequestInfo struct {
	Id        string `json:"id"`
	TestRunId string `json:"testRunId,omitempty"`
}
