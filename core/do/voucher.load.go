package do

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"

	dodbs "github.com/fido-alliance/iot-fdo-conformance-tools/core/do/dbs"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
)

const (
	testVoucherFolder string = "./_test_vouchers/"
	voucherSuffix     string = ".voucher.pem"
)

func LoadLocalVouchers(db *dodbs.VoucherDB) error {
	folderEntries, err := os.ReadDir(testVoucherFolder)
	if err != nil {
		return fmt.Errorf("Error reading directory \"%s\". %s", testVoucherFolder, err.Error())
	}

	var voucherPaths []string
	var voucherGUIDs []fdoshared.FdoGuid

	for _, folderEntry := range folderEntries {
		if folderEntry.IsDir() || !strings.HasSuffix(folderEntry.Name(), voucherSuffix) {
			log.Println("Skipping " + folderEntry.Name())
			continue
		}

		u, err := uuid.Parse(strings.TrimSuffix(folderEntry.Name(), voucherSuffix))
		if err != nil {
			return fmt.Errorf("Error parsing UUID from file name \"%s\". %s", folderEntry.Name(), err.Error())
		}

		voucherPaths = append(voucherPaths, path.Join(testVoucherFolder, folderEntry.Name()))
		voucherGUIDs = append(voucherGUIDs, [16]byte(u))
	}

	for i := range voucherPaths {
		fileBytes, err := os.ReadFile(voucherPaths[i])
		if err != nil {
			return fmt.Errorf("Error reading file \"%s\". %s ", voucherPaths[i], err.Error())
		}

		if len(fileBytes) == 0 {
			return fmt.Errorf("Error reading file \"%s\". The file is empty.", voucherPaths[i])
		}

		voucherBlock, rest := pem.Decode(fileBytes)
		if voucherBlock == nil {
			return fmt.Errorf("%s: Could not find voucher PEM data!", voucherPaths[i])
		}

		if voucherBlock.Type != fdoshared.OWNERSHIP_VOUCHER_PEM_TYPE {
			return fmt.Errorf("%s: Failed to decode PEM voucher. Unexpected type: %s", voucherPaths[i], voucherBlock.Type)
		}

		privateKeyBytes, _ := pem.Decode(rest)
		if privateKeyBytes == nil {
			return fmt.Errorf("%s: Could not find key PEM data!", voucherPaths[i])
		}

		// CBOR decode voucher

		var voucherInst fdoshared.OwnershipVoucher
		err = fdoshared.CborCust.Unmarshal(voucherBlock.Bytes, &voucherInst)
		if err != nil {
			return fmt.Errorf("%s: Could not CBOR unmarshal voucher! %s", voucherPaths[i], err.Error())
		}

		log.Println("Loading voucher " + hex.EncodeToString(voucherGUIDs[i][:]))

		if err := db.SaveByGUID(voucherGUIDs[i], fdoshared.VoucherDBEntry{
			Voucher:        voucherInst,
			PrivateKeyX509: privateKeyBytes.Bytes,
		}); err != nil {
			return fmt.Errorf("Error saving voucher %s. %s", hex.EncodeToString(voucherGUIDs[i][:]), err.Error())
		}
	}

	return nil
}
