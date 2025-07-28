package testexec

import (
	testdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/request"
)

func ExecuteDOTestsTo2(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
	reqtDB.StartNewRun(reqte.Uuid)

	executeTo2_60(reqte, reqtDB)
	executeTo2_62(reqte, reqtDB)
	executeTo2_64(reqte, reqtDB)
	executeTo2_66(reqte, reqtDB)
	executeTo2_68(reqte, reqtDB)
	executeTo2_70(reqte, reqtDB)

	reqtDB.FinishRun(reqte.Uuid)
}
