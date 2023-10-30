package fdoshared

import (
	"fmt"
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

func GetSim(sims []ServiceInfoKV, simID SIM_ID) ([]byte, bool) {
	for _, sim := range sims {
		if sim.ServiceInfoKey == simID {
			return sim.ServiceInfoVal, false
		}
	}

	return nil, true
}

func GetDeviceOSSims() []ServiceInfoKV {
	return []ServiceInfoKV{
		{
			ServiceInfoKey: SIM_DEVMOD_ACTIVE,
			ServiceInfoVal: CBOR_TRUE,
		},
		{
			ServiceInfoKey: SIM_DEVMOD_OS,
			ServiceInfoVal: []byte(runtime.GOOS),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_ARCH,
			ServiceInfoVal: []byte(runtime.GOARCH),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_VERSION,
			ServiceInfoVal: []byte(runtime.Version()),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_DEVICE,
			ServiceInfoVal: []byte("FIDO Device Onboard Virtual Device"),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_SEP,
			ServiceInfoVal: []byte(";"),
		},
		{
			ServiceInfoKey: SIM_DEVMOD_BIN,
			ServiceInfoVal: []byte(runtime.GOARCH),
		},
	}
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
			var devModVal []string
			err = cbor.Unmarshal(sim.ServiceInfoVal, &devModVal)
			if err == nil {
				result.SIM_DEVMOD_MODULES = &devModVal
			}

			// TODO: Optional modules
		}

		if err != nil {
			return nil, fmt.Errorf("error decoding %s sim. %s", sim.ServiceInfoKey, err.Error())
		}
	}

	return &result, nil
}

func CastServiceInfo(serviceInfoIntf interface{}) ServiceInfoKV {
	return serviceInfoIntf.(ServiceInfoKV)
}

func UintToBytes(val uint) []byte {
	result, _ := cbor.Marshal(val)
	return result
}

func SimsListToBytes(sims SIM_IDS) []byte {
	result, _ := cbor.Marshal(sims)
	return result
}
