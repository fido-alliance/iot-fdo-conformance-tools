package to2

import (
	"encoding/hex"
	"testing"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
)

func TestValidateDeviceSIMs(t *testing.T) {
	guid := fdoshared.NewFdoGuid_FIDO()

	var TEST_INTEL [][]string = [][]string{
		{"devmod:active", "F5"},
		{"devmod:os", "654C696E7578"},
		{"devmod:arch", "63783836"},
		{"devmod:version", "695562756E74752D3134"},
		{"devmod:device", "6F496E74656C2D46444F2D4C696E7578"},
		{"devmod:sn", "6E66646F2D6C696E75782D31323334"},
		{"devmod:pathsep", "612F"},
		{"devmod:sep", "613B"},
		{"devmod:nl", "610A"},
		{"devmod:tmp", "60"},
		{"devmod:dir", "60"},
		{"devmod:progenv", "627368"},
		{"devmod:bin", "63783836"},
		{"devmod:mudurl", "60"},
		{"devmod:nummodules", "01"},
		{"devmod:modules", "8301016D6669646F5F616C6C69616E6365"},
	}

	sims := []fdoshared.ServiceInfoKV{}

	for _, rawsim := range TEST_INTEL {
		simval, _ := hex.DecodeString(rawsim[1])
		sim := fdoshared.ServiceInfoKV{
			ServiceInfoKey: fdoshared.SIM_ID(rawsim[0]),
			ServiceInfoVal: simval,
		}
		sims = append(sims, sim)
	}

	// Test with valid SIMs
	result, err := ValidateDeviceSIMs(guid, sims)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Errorf("Expected non-nil result")
	}

	// Test with missing mandatory SIMs
	fdoshared.MANDATORY_SIMS = fdoshared.SIM_IDS{"sim1", "sim2", "sim3"}
	result, err = ValidateDeviceSIMs(guid, sims)
	if err == nil {
		t.Errorf("Expected error, but got nil")
	}
	if result != nil {
		t.Errorf("Expected nil result, but got %v", result)
	}

	// Test with invalid SIMs
	sims = []fdoshared.ServiceInfoKV{
		{ServiceInfoKey: fdoshared.SIM_ID("invalid-sim")},
	}
	result, err = ValidateDeviceSIMs(guid, sims)
	if err == nil {
		t.Errorf("Expected error, but got nil")
	}
	if result != nil {
		t.Errorf("Expected nil result, but got %v", result)
	}
}
