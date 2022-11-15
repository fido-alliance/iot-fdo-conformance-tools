package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"sync"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

const SeedingSize = 100000

type SeedRunResult struct {
	DeviceSgType fdoshared.DeviceSgType
	Guids        []fdoshared.FdoGuid
	CredBases    []fdoshared.WawDeviceCredBase
	Error        error
}

func SeedRunInst(sgType fdoshared.DeviceSgType, wg *sync.WaitGroup, resultChannel chan SeedRunResult) {
	var result = SeedRunResult{
		DeviceSgType: sgType,
		Guids:        []fdoshared.FdoGuid{},
		CredBases:    []fdoshared.WawDeviceCredBase{},
	}

	defer wg.Done()

	log.Printf("----- Starting SgType %d. -----\n", sgType)
	getSgAlgInfo, err := fdoshared.GetAlgInfoFromSgType(sgType)
	if err != nil {
		result.Error = errors.New("Error getting AlgInfo. " + err.Error())

		resultChannel <- result
		return
	}

	for i := 0; i < SeedingSize; i++ {
		if i != 0 && i%(SeedingSize/10) == 0 {
			log.Printf("%d. %d%% completed\n", sgType, int(math.Floor(float64(i/(SeedingSize/10))))*10)
		}
		// log.Printf("No %d: Generating device base %d... ", i, sgType)
		newDeviceBase, err := fdoshared.NewWawDeviceCredBase(getSgAlgInfo.HmacType, sgType)
		if err != nil {
			result.Error = fmt.Errorf("Error generating device base for sgType %d. " + err.Error())

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

	chn := make(chan SeedRunResult, len(fdoshared.DeviceSgTypeList))

	for _, sgType := range fdoshared.DeviceSgTypeList {
		if sgType == fdoshared.StEPID10 || sgType == fdoshared.StEPID11 {
			log.Println("EPID is not currently supported!")
			continue
		}

		wg.Add(1)

		go SeedRunInst(sgType, &wg, chn)
	}

	wg.Wait()

	var newConfig dbs.MainConfig = dbs.MainConfig{
		SeededGuids: fdoshared.FdoSeedIDs{},
	}

	var results []SeedRunResult = []SeedRunResult{}
	for i := 0; i < len(fdoshared.DeviceSgTypeList); i++ {
		result := <-chn
		results = append(results, result)

		if result.Error != nil {
			return fmt.Errorf("Failed to pre-generate creds for %d. %s ", result.DeviceSgType, result.Error)
		}

		for _, newDeviceBase := range result.CredBases {
			err := devbasedb.Save(newDeviceBase)
			if err != nil {
				return fmt.Errorf("Error saving device base. " + err.Error())
			}
		}

		newConfig.SeededGuids[result.DeviceSgType] = result.Guids
		log.Println(len(newConfig.SeededGuids[result.DeviceSgType]))
	}

	err := configdb.Save(newConfig)
	if err != nil {
		return fmt.Errorf("Error saving config. " + err.Error())
	}

	log.Println("Done!")

	return nil
}
