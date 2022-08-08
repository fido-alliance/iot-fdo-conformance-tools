package fdodo

import (
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

const TEST_VOUCHER_LOC string = "./_test_vouchers/"
const OWNERSHIP_VOUCHER_PEM_TYPE string = "OWNERSHIP VOUCHER"

func GetVoucherFileList() ([]string, error) {
	var voucherFiles []string

	folderEntries, err := ioutil.ReadDir(TEST_VOUCHER_LOC)
	if err != nil {
		return []string{}, fmt.Errorf("Error reading directory \"%s\". %s", TEST_VOUCHER_LOC, err.Error())
	}

	for _, folderEntry := range folderEntries {
		if folderEntry.IsDir() || !strings.HasSuffix(folderEntry.Name(), ".voucher.pem") {
			log.Println("Skipping " + folderEntry.Name())
			continue
		}

		voucherFiles = append(voucherFiles, TEST_VOUCHER_LOC+folderEntry.Name())
	}

	return voucherFiles, nil
}

func LoadLocalVouchers() ([]fdoshared.VoucherDBEntry, error) {
	var vouchers []fdoshared.VoucherDBEntry

	fileList, err := GetVoucherFileList()
	if err != nil {
		return []fdoshared.VoucherDBEntry{}, errors.New("Error getting vouchers file list. " + err.Error())
	}

	for _, fileLoc := range fileList {
		fileBytes, err := os.ReadFile(fileLoc)
		if err != nil {
			return []fdoshared.VoucherDBEntry{}, fmt.Errorf("Error reading file \"%s\". %s ", fileLoc, err.Error())
		}

		if len(fileBytes) == 0 {
			return vouchers, fmt.Errorf("Error reading file \"%s\". The file is empty.", fileLoc)
		}

		voucherBlock, rest := pem.Decode(fileBytes)
		if voucherBlock == nil {
			return vouchers, fmt.Errorf("%s: Could not find voucher PEM data!", fileLoc)
		}

		if voucherBlock.Type != OWNERSHIP_VOUCHER_PEM_TYPE {
			return vouchers, fmt.Errorf("%s: Failed to decode PEM voucher. Unexpected type: %s", fileLoc, voucherBlock.Type)
		}

		privateKeyBytes, rest := pem.Decode(rest)
		if privateKeyBytes == nil {
			return vouchers, fmt.Errorf("%s: Could not find key PEM data!", fileLoc)
		}

		// CBOR decode voucher

		var voucherInst fdoshared.OwnershipVoucher
		err = cbor.Unmarshal(voucherBlock.Bytes, &voucherInst)
		if err != nil {
			return vouchers, fmt.Errorf("%s: Could not CBOR unmarshal voucher! %s", fileLoc, err.Error())
		}

		ovHeader, _ := voucherInst.GetOVHeader()
		log.Println("Loading voucher " + hex.EncodeToString(ovHeader.OVGuid[:]))

		vouchers = append(vouchers, fdoshared.VoucherDBEntry{
			Voucher:        voucherInst,
			PrivateKeyX509: privateKeyBytes.Bytes,
		})
	}

	return vouchers, nil

}
