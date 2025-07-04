package fdoshared

import (
	"fmt"
	"log"
	"runtime"

	"github.com/fxamacker/cbor/v2"
)

type ServiceInfoKV struct {
	_              struct{} `cbor:",toarray"`
	ServiceInfoKey SIM_ID
	ServiceInfoVal []byte
}

type SIMS []ServiceInfoKV

func (h *SIMS) GetSimIDs() SIM_IDS {
	result := SIM_IDS{}

	for _, sim := range *h {
		result = append(result, sim.ServiceInfoKey)
	}

	return result
}

func (h *SIMS) GetSim(simID SIM_ID) ([]byte, bool) {
	for _, sim := range *h {
		log.Println(sim.ServiceInfoKey, simID)
		if sim.ServiceInfoKey == simID {
			return sim.ServiceInfoVal, true
		}
	}

	return nil, false
}

func GetDeviceOSSims() []ServiceInfoKV {
	deviceSims := []ServiceInfoKV{
		{
			ServiceInfoKey: SIM_DEVMOD_ACTIVE,
			ServiceInfoVal: CBOR_TRUE,
		},
		{
			ServiceInfoKey: SIM_DEVMOD_OS,
			ServiceInfoVal: StringToCborBytes(runtime.GOOS),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_ARCH,
			ServiceInfoVal: StringToCborBytes(runtime.GOARCH),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_VERSION,
			ServiceInfoVal: StringToCborBytes(runtime.Version()),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_DEVICE,
			ServiceInfoVal: StringToCborBytes("FIDO Device Onboard Virtual Device"),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_SEP,
			ServiceInfoVal: StringToCborBytes(";"),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_BIN,
			ServiceInfoVal: StringToCborBytes(runtime.GOARCH),
		},
	}

	deviceSims = append(deviceSims, ServiceInfoKV{
		ServiceInfoKey: SIM_DEVMOD_NUMMODULES,
		ServiceInfoVal: UintToCborBytes(1),
	})

	deviceSims = append(deviceSims, ServiceInfoKV{
		ServiceInfoKey: SIM_DEVMOD_MODULES,
		ServiceInfoVal: SimsListToBytes(SIM_IDS{
			IOPLOGGER_SIM_NAME,
		}),
	})

	return deviceSims
}

type RESULT_SIMS struct {
	_                     struct{} `cbor:",toarray"`
	SIM_DEVMOD_ACTIVE     *bool
	SIM_DEVMOD_OS         *string
	SIM_DEVMOD_ARCH       *string
	SIM_DEVMOD_VERSION    *string
	SIM_DEVMOD_DEVICE     *string
	SIM_DEVMOD_SN         *interface{}
	SIM_DEVMOD_PATHSEP    *string
	SIM_DEVMOD_SEP        *string
	SIM_DEVMOD_NL         *string
	SIM_DEVMOD_TMP        *string
	SIM_DEVMOD_DIR        *string
	SIM_DEVMOD_PROGENV    *string
	SIM_DEVMOD_BIN        *string
	SIM_DEVMOD_MUDURL     *uint
	SIM_DEVMOD_NUMMODULES *uint
	SIM_DEVMOD_MODULES    *[]string
}

func DecodeSims(sims []ServiceInfoKV) (*RESULT_SIMS, error) {
	result := RESULT_SIMS{}

	for _, sim := range sims {
		var err error = nil
		switch sim.ServiceInfoKey {
		// Mandatory modules
		case SIM_DEVMOD_ACTIVE:
			var devModVal bool
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_ACTIVE = &devModVal
			}

		case SIM_DEVMOD_OS:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_OS = &devModVal
			}

		case SIM_DEVMOD_ARCH:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_ARCH = &devModVal
			}

		case SIM_DEVMOD_VERSION:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_VERSION = &devModVal
			}

		case SIM_DEVMOD_DEVICE:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_DEVICE = &devModVal
			}

		case SIM_DEVMOD_SEP:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_SEP = &devModVal
			}

		case SIM_DEVMOD_BIN:
			var devModVal string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_BIN = &devModVal
			}

		case SIM_DEVMOD_NUMMODULES:
			var devModVal uint
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_NUMMODULES = &devModVal
			}

		case SIM_DEVMOD_MODULES:
			if result.SIM_DEVMOD_MODULES == nil {
				result.SIM_DEVMOD_MODULES = &[]string{}
			}

			var devModVal []interface{}
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				if len(devModVal) < 3 {
					return nil, fmt.Errorf("invalid SIM_DEVMOD_MODULES")
				}

				_, ok := devModVal[0].(uint64)
				if !ok {
					return nil, fmt.Errorf("invalid SIM_DEVMOD_MODULES. First element must be uint")
				}

				_, ok = devModVal[1].(uint64)
				if !ok {
					return nil, fmt.Errorf("invalid SIM_DEVMOD_MODULES. Second element must be uint")
				}

				restItems := devModVal[2:]

				for _, item := range restItems {
					itemStr, ok := item.(string)
					if !ok {
						return nil, fmt.Errorf("invalid SIM_DEVMOD_MODULES. Item must be string")
					}

					*result.SIM_DEVMOD_MODULES = append(*result.SIM_DEVMOD_MODULES, itemStr)
				}
			}

			// TODO: Optional modules
		}

		if err != nil {
			return nil, fmt.Errorf("error decoding %s sim. %s", sim.ServiceInfoKey, err.Error())
		}
	}

	return &result, nil
}

func UintToCborBytes(val uint) []byte {
	result, _ := cbor.Marshal(val)
	return result
}

func StringToCborBytes(val string) []byte {
	result, _ := cbor.Marshal(val)
	return result
}

func SimsListToBytes(sims SIM_IDS) []byte {
	var resultList []interface{} = []interface{}{
		1,
		uint(len(sims)),
	}

	for _, sim := range sims {
		resultList = append(resultList, sim)
	}

	result, _ := cbor.Marshal(resultList)
	return result
}
