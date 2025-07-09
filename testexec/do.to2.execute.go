package testexec

import (
	"fmt"
	"log"
	"sync"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	testdbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/dbs"
	reqtestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/request"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"
)

const (
	TEST_POSITIVE_BATCH_SIZE int = 20
	TEST_POSITIVE_BATCHES    int = 5
)

const TEST_NEGATIVE_PER_TEST_VOUCHERS int = 5

type GenVouchersResult struct {
	TestID                testcom.FDOTestID
	DeviceCredAndVouchers []fdoshared.DeviceCredAndVoucher
	Error                 error
}

func GenerateTo2Vouchers_Thread(testId testcom.FDOTestID, guids fdoshared.FdoGuidList, devDB *dbs.DeviceBaseDB, wg *sync.WaitGroup, resultChannel chan GenVouchersResult) {
	log.Printf("Starting %s", testId)
	defer wg.Done()
	var genVouchersResult GenVouchersResult = GenVouchersResult{
		TestID:                testId,
		DeviceCredAndVouchers: []fdoshared.DeviceCredAndVoucher{},
	}

	for _, guid := range guids {
		testCred, err := devDB.GetVANDV(guid, testId)
		if err != nil {
			genVouchersResult.Error = fmt.Errorf("Error generating voucher %s for test %s. %s", guid.GetFormatted(), testId, err.Error())
			break
		}

		genVouchersResult.DeviceCredAndVouchers = append(genVouchersResult.DeviceCredAndVouchers, *testCred)
	}

	log.Printf("Done %s", testId)

	resultChannel <- genVouchersResult
}

func GenerateTo2Vouchers(guidList fdoshared.FdoGuidList, devDB *dbs.DeviceBaseDB) (map[testcom.FDOTestID][]fdoshared.DeviceCredAndVoucher, error) {
	var vouchers map[testcom.FDOTestID][]fdoshared.DeviceCredAndVoucher = map[testcom.FDOTestID][]fdoshared.DeviceCredAndVoucher{}

	totalThreads := len(testcom.FIDO_TEST_LIST_VOUCHER) + TEST_POSITIVE_BATCHES

	var wg sync.WaitGroup

	chn := make(chan GenVouchersResult, totalThreads)

	testsLen := len(testcom.FIDO_TEST_LIST_VOUCHER)
	randomGuids := guidList.GetRandomSelection(testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS + TEST_POSITIVE_BATCHES*TEST_POSITIVE_BATCH_SIZE)

	randomNegativeTestGuids := randomGuids[0 : testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS]

	for i, testId := range testcom.FIDO_TEST_LIST_VOUCHER {
		indexStart := i * TEST_NEGATIVE_PER_TEST_VOUCHERS
		indexEnd := (i + 1) * TEST_NEGATIVE_PER_TEST_VOUCHERS

		wg.Add(1)
		go GenerateTo2Vouchers_Thread(testId, randomNegativeTestGuids[indexStart:indexEnd], devDB, &wg, chn)
	}

	randomPositiveTestGuids := randomGuids[testsLen*TEST_NEGATIVE_PER_TEST_VOUCHERS:]
	for i := 0; i < TEST_POSITIVE_BATCHES; i++ {
		indexStart := i * TEST_POSITIVE_BATCH_SIZE
		indexEnd := (i + 1) * TEST_POSITIVE_BATCH_SIZE

		wg.Add(1)
		go GenerateTo2Vouchers_Thread(testcom.NULL_TEST, randomPositiveTestGuids[indexStart:indexEnd], devDB, &wg, chn)
	}

	for i := 0; i < totalThreads; i++ {
		result := <-chn

		if result.Error != nil {
			return nil, result.Error
		}

		vouchers[result.TestID] = append(vouchers[result.TestID], result.DeviceCredAndVouchers...)
	}

	wg.Wait()

	return vouchers, nil
}

func ExecuteDOTestsTo2(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
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
