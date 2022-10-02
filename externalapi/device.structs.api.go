package externalapi

import (
	listenertestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/listener_tests_deps"
)

type Device_CreateTestCase struct {
	Name                 string `name:"url"`
	VoucherAndPrivateKey string `voucher:"url"`
}

type Device_Item struct {
	Id   string                              `json:"id"`
	Name string                              `json:"name"`
	To0  []listenertestsdeps.ListenerTestRun `json:"to0"`
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
