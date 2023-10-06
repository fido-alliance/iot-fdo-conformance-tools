package common

import (
	"encoding/pem"
	"errors"
	"fmt"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
)

func DecodePemVoucherAndKey(vandvpem string) (*fdoshared.VoucherDBEntry, error) {
	var vandvpemBytes []byte = []byte(vandvpem)

	if len(vandvpem) == 0 {
		return nil, errors.New("Error parsing pem voucher and key. The input is empty")
	}

	voucherBlock, rest := pem.Decode(vandvpemBytes)
	if voucherBlock == nil {
		return nil, errors.New("Could not find voucher PEM data!")
	}

	if voucherBlock.Type != fdoshared.OWNERSHIP_VOUCHER_PEM_TYPE {
		return nil, fmt.Errorf("Failed to decode PEM voucher. Unexpected type: %s", voucherBlock.Type)
	}

	privateKeyBytes, rest := pem.Decode(rest)
	if privateKeyBytes == nil {
		return nil, errors.New("Could not find key PEM data!")
	}

	// CBOR decode voucher

	var voucherInst fdoshared.OwnershipVoucher
	err := fdoshared.CborCust.Unmarshal(voucherBlock.Bytes, &voucherInst)
	if err != nil {
		return nil, fmt.Errorf("Could not CBOR unmarshal voucher! %s", err.Error())
	}

	err = voucherInst.Validate()
	if err != nil {
		return nil, fmt.Errorf("Could not validate voucher inst! %s", err.Error())
	}

	return &fdoshared.VoucherDBEntry{
		Voucher:        voucherInst,
		PrivateKeyX509: privateKeyBytes.Bytes,
	}, nil
}
