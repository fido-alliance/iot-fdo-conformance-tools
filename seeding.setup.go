package main

import (
	"fmt"
	"log"
	"sync"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
)

const SeedingSize = 10000
const ThreadsPerAlg = 10

type SeedRunResult struct {
	DeviceSgType fdoshared.DeviceSgType
	Guids        []fdoshared.FdoGuid
	CredBases    []fdoshared.WawDeviceCredBase
	Error        error
}

func SeedRunInst(threadID int, seedSize int, sgType fdoshared.DeviceSgType, wg *sync.WaitGroup, resultChannel chan SeedRunResult) {
	var result = SeedRunResult{
		DeviceSgType: sgType,
		Guids:        []fdoshared.FdoGuid{},
		CredBases:    []fdoshared.WawDeviceCredBase{},
	}

	defer wg.Done()

	log.Printf("----- [%d] Starting SgType %d. -----\n", threadID, sgType)
	getSgAlgInfo, ok := fdoshared.SgTypeInfoMap[sgType]
	if !ok {
		result.Error = fmt.Errorf("unsupported sgType %d", sgType)
		log.Println(result.Error.Error())
		resultChannel <- result
		return
	}

	for i := 0; i < seedSize; i++ {
		if i != 0 && i%(seedSize/10) == 0 {
			log.Printf("[%d] %d. %d%% completed\n", threadID, sgType, int(float64(i/(seedSize/10)))*10)
		}

		newDeviceBase, err := fdoshared.NewWawDeviceCredBase(getSgAlgInfo.HmacType, sgType)
		if err != nil {
			result.Error = fmt.Errorf("[%d] Error generating device base for sgType %d. %s ", threadID, sgType, err.Error())
			log.Println(result.Error.Error())
			resultChannel <- result
			return
		}

		result.CredBases = append(result.CredBases, *newDeviceBase)
		result.Guids = append(result.Guids, newDeviceBase.FdoGuid)
	}

	resultChannel <- result
}

func PreSeed(configdb *dbs.ConfigDB, devbasedb *dbs.DeviceBaseDB) error {
	var wg sync.WaitGroup

	totalChannels := len(fdoshared.DeviceSgTypeList) * ThreadsPerAlg
	chn := make(chan SeedRunResult, totalChannels)
	var batchSize int = SeedingSize / ThreadsPerAlg

	for _, sgType := range fdoshared.DeviceSgTypeList {
		if sgType == fdoshared.StEPID10 || sgType == fdoshared.StEPID11 {
			log.Println("EPID is not currently supported!")
			continue
		}

		for i := 0; i < ThreadsPerAlg; i++ {
			wg.Add(1)
			go SeedRunInst(i, batchSize, sgType, &wg, chn)
		}
	}

	wg.Wait()

	var newConfig dbs.MainConfig = dbs.MainConfig{
		SeededGuids: fdoshared.FdoSeedIDs{},
	}

	for i := 0; i < totalChannels; i++ {
		result := <-chn

		if result.Error != nil {
			return fmt.Errorf("failed to pre-generate creds for %d. %s ", result.DeviceSgType, result.Error)
		}

		for _, newDeviceBase := range result.CredBases {
			err := devbasedb.Save(newDeviceBase)
			if err != nil {
				return fmt.Errorf("Error saving device base. " + err.Error())
			}
		}

		newConfig.SeededGuids[result.DeviceSgType] = append(newConfig.SeededGuids[result.DeviceSgType], result.Guids...)
	}

	err := configdb.Save(newConfig)
	if err != nil {
		return fmt.Errorf("error saving config. " + err.Error())
	}

	log.Println("Done!")

	return nil
}
