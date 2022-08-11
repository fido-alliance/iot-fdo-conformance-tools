package externalapi

import (
	"github.com/WebauthnWorks/fdo-fido-conformance-server/rvtdeps"
)

type RVT_CreateTestCase struct {
	Url string `json:"url"`
}

type RVT_Inst struct {
	Id  string `json:"id"`
	Url string `json:"url"`
}

type RVT_ListRvts struct {
	Rvts        []RVT_Inst `json:"rvts"`
	TEMPREsults []rvtdeps.RVTestRun
	Status      FdoConfApiStatus `json:"status"`
}

type RVT_ExecureReq struct {
	Id string `json:"id"`
}
