package testcom

import (
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/google/uuid"
)

type FDOConformanceResults_Vendor struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Phone   string `json:"phone"`
}

type FDOConformanceResults_Passed struct {
	To0 []FDOTestID `json:"to0d,omitempty"`
	To1 []FDOTestID `json:"to1d,omitempty"`
	To2 []FDOTestID `json:"to2d,omitempty"`
}

type FDOConformanceResults_Implementation struct {
	Guid  string                           `json:"uuid,omitempty"`
	Class fdoshared.FdoImplementationClass `json:"class"`
	Name  string                           `json:"name"`
}

type FDOConformanceResults struct {
	Passed         FDOConformanceResults_Passed         `json:"passed"`
	Implementation FDOConformanceResults_Implementation `json:"implementation"`
	VendorInfo     FDOConformanceResults_Vendor         `json:"vendorInfo,omitempty"`
}

func NewResults_Device(
	implementationName string,
	guid fdoshared.FdoGuid,
	vendorInfo FDOConformanceResults_Vendor,
	to1 []FDOTestID,
	to2 []FDOTestID,
) FDOConformanceResults {
	uuidInst, _ := uuid.FromBytes(guid[:])
	uuidFormatted, _ := uuidInst.MarshalText()

	return FDOConformanceResults{
		Passed: FDOConformanceResults_Passed{To1: to1, To2: to2},
		Implementation: FDOConformanceResults_Implementation{
			Guid:  string(uuidFormatted),
			Class: fdoshared.Device,
			Name:  implementationName,
		},
		VendorInfo: vendorInfo,
	}
}

func NewResults_DeviceOnboardingService(
	implementationName string,
	vendorInfo FDOConformanceResults_Vendor,
	to0 []FDOTestID,
	to2 []FDOTestID,
) FDOConformanceResults {
	return FDOConformanceResults{
		Passed: FDOConformanceResults_Passed{To0: to0, To2: to2},
		Implementation: FDOConformanceResults_Implementation{
			Class: fdoshared.DeviceOnboardingService,
			Name:  implementationName,
		},
		VendorInfo: vendorInfo,
	}
}

func NewResults_RendezvousService(
	implementationName string,
	vendorInfo FDOConformanceResults_Vendor,
	to0 []FDOTestID,
	to1 []FDOTestID,
) FDOConformanceResults {
	return FDOConformanceResults{
		Passed: FDOConformanceResults_Passed{To0: to0, To1: to1},
		Implementation: FDOConformanceResults_Implementation{
			Class: fdoshared.RendezvousServer,
			Name:  implementationName,
		},
		VendorInfo: vendorInfo,
	}
}
