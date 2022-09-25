package testexec

import (
	"fmt"
	"log"

	fdodeviceimplementation "github.com/WebauthnWorks/fdo-device-implementation"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-fido-conformance-server/req_tests_deps"
	"github.com/WebauthnWorks/fdo-fido-conformance-server/testcom"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

const TEST_POSITIVE_VOUCHERS int = 100
const TEST_NEGATIVE_PER_TEST_VOUCHERS int = 5

// TODO: Optimise // Parallelize
func GenerateTo2Vouchers(guidList fdoshared.FdoGuidList, devDB *dbs.DeviceBaseDB) (map[testcom.FDOTestID][]fdodeviceimplementation.DeviceCredAndVoucher, error) {
	var vouchers map[testcom.FDOTestID][]fdodeviceimplementation.DeviceCredAndVoucher = map[testcom.FDOTestID][]fdodeviceimplementation.DeviceCredAndVoucher{}

	testsLen := len(testcom.FIDO_TEST_LIST_VOUCHER)
	randomGuids := guidList.GetRandomSelection(testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS + TEST_POSITIVE_VOUCHERS)

	randomPositiveTestGuids := randomGuids[testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS:]
	randomNegativeTestGuids := randomGuids[0 : testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS]
	for i, testId := range testcom.FIDO_TEST_LIST_VOUCHER {
		vouchers[testId] = []fdodeviceimplementation.DeviceCredAndVoucher{}
		for j := 0; j < TEST_NEGATIVE_PER_TEST_VOUCHERS; j++ {
			arrIndex := i*TEST_NEGATIVE_PER_TEST_VOUCHERS + j

			log.Printf("Generating voucher %d for test %s", arrIndex, testId)
			guid := randomNegativeTestGuids[arrIndex]

			testCred, err := devDB.GetVANDV(guid, testId)
			if err != nil {
				return vouchers, fmt.Errorf("Error generating voucher %d %s for test %s. %s", arrIndex, guid.GetFormatted(), testId, err.Error())
			}

			vouchers[testId] = append(vouchers[testId], *testCred)
		}
	}

	vouchers[testcom.NULL_TEST] = []fdodeviceimplementation.DeviceCredAndVoucher{}
	for i, guid := range randomPositiveTestGuids {
		log.Printf("Generating positive voucher %d", i)

		positiveTestCred, err := devDB.GetVANDV(guid, testcom.NULL_TEST)
		if err != nil {
			return vouchers, fmt.Errorf("Error generating voucher %d %s for test %s. %s", i, guid.GetFormatted(), testcom.NULL_TEST, err.Error())
		}

		vouchers[testcom.NULL_TEST] = append(vouchers[testcom.NULL_TEST], *positiveTestCred)
	}

	return vouchers, nil
}

func ExecuteDOTestsTo2(reqte reqtestsdeps.RequestTestInst, reqtDB *dbs.RequestTestDB) {
	reqtDB.StartNewRun(reqte.Uuid)

	executeTo2_60(reqte, reqtDB)
	executeTo2_60_Vouchers(reqte, reqtDB)
	executeTo2_62(reqte, reqtDB)
	executeTo2_64(reqte, reqtDB)
	executeTo2_66(reqte, reqtDB)
	executeTo2_68(reqte, reqtDB)
	executeTo2_70(reqte, reqtDB)

	reqtDB.FinishRun(reqte.Uuid)
}
