package device

import (
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
)

const DEVICE_CREDENTIAL_LOC string = "./_dis/"

func GetCredentials() ([]string, error) {
	var credentialFiles []string

	folderEntries, err := os.ReadDir(DEVICE_CREDENTIAL_LOC)
	if err != nil {
		return []string{}, fmt.Errorf("Error reading directory \"%s\". %s", DEVICE_CREDENTIAL_LOC, err.Error())
	}

	for _, folderEntry := range folderEntries {
		if folderEntry.IsDir() || !strings.HasSuffix(folderEntry.Name(), ".dis.pem") {
			log.Println("Skipping " + folderEntry.Name())
			continue
		}
		credentialFiles = append(credentialFiles, DEVICE_CREDENTIAL_LOC+folderEntry.Name())
		return credentialFiles, nil // return first result
	}
	return nil, nil
}

func LoadLocalCredentials() (fdoshared.WawDeviceCredential, error) {
	var credential fdoshared.WawDeviceCredential

	fileList, err := GetCredentials()
	if err != nil {
		return credential, errors.New("Error getting vouchers file list. " + err.Error())
	}

	for _, fileLoc := range fileList {
		fileBytes, err := os.ReadFile(fileLoc)
		if err != nil {
			return credential, fmt.Errorf("Error reading file \"%s\". %s ", fileLoc, err.Error())
		}

		if len(fileBytes) == 0 {
			return credential, fmt.Errorf("Error reading file \"%s\". The file is empty.", fileLoc)
		}

		credentialBlock, _ := pem.Decode(fileBytes)
		if credentialBlock == nil {
			return credential, fmt.Errorf("%s: Could not find voucher PEM data!", fileLoc)
		}

		if credentialBlock.Type != fdoshared.CREDENTIAL_PEM_TYPE {
			return credential, fmt.Errorf("%s: Failed to decode PEM voucher. Unexpected type: %s", fileLoc, credentialBlock.Type)
		}

		var credentialInst fdoshared.WawDeviceCredential
		err = fdoshared.CborCust.Unmarshal(credentialBlock.Bytes, &credentialInst)
		if err != nil {
			return credential, fmt.Errorf("%s: Could not CBOR unmarshal voucher! %s", fileLoc, err.Error())
		}

		return credentialInst, nil
	}

	return credential, nil
}
