package device

import (
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom"
)

const DIS_LOCATION string = "./_dis"
const VOUCHERS_LOCATION string = "./_vouchers"

func GenerateOvEntry(
	prevEntryHash fdoshared.HashOrHmac,
	hdrHash fdoshared.HashOrHmac,
	mfgPrivateKey interface{},
	prevEntrySgType fdoshared.DeviceSgType,
	newEntrySgType fdoshared.DeviceSgType,
	testId testcom.FDOTestID,
) (interface{}, []byte, *fdoshared.CoseSignature, error) {
	// Generate manufacturer private key.
	newOVEPrivateKey, newOVEPublicKey, err := fdoshared.GenerateVoucherKeypair(newEntrySgType)
	if err != nil {
		return nil, []byte{}, nil, err
	}

	if testId == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_PUBKEY {
		newOVEPublicKey = fdoshared.Conf_RandomTestFuzzPublicKey(*newOVEPublicKey)
	}

	ovEntryPayload := fdoshared.OVEntryPayload{
		OVEHashPrevEntry: prevEntryHash,
		OVEHashHdrInfo:   hdrHash,
		OVEExtra:         nil,
		OVEPubKey:        *newOVEPublicKey,
	}

	ovEntryPayloadBytes, err := fdoshared.CborCust.Marshal(ovEntryPayload)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error marshaling OVEntry. " + err.Error())
	}

	protectedHeader := fdoshared.ProtectedHeader{
		Alg: fdoshared.GetIntRef(int(prevEntrySgType)),
	}

	ovEntry, err := fdoshared.GenerateCoseSignature(ovEntryPayloadBytes, protectedHeader, fdoshared.UnprotectedHeader{}, mfgPrivateKey, prevEntrySgType)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error generating OVEntry. " + err.Error())
	}

	marshaledPrivateKey, err := fdoshared.MarshalPrivateKey(newOVEPrivateKey, newEntrySgType)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error marshaling private key. " + err.Error())
	}

	return newOVEPrivateKey, marshaledPrivateKey, ovEntry, nil
}

func NewVirtualDeviceAndVoucher(newDi fdoshared.WawDeviceCredential, voucherSgType fdoshared.DeviceSgType, ovRVInfo []fdoshared.RendezvousInstrList, fdoTestID testcom.FDOTestID) (*fdoshared.DeviceCredAndVoucher, error) {
	// Generate manufacturer private key.
	mfgPrivateKey, mfgPublicKey, err := fdoshared.GenerateVoucherKeypair(voucherSgType)
	if err != nil {
		return nil, errors.New("Error generating new manufacturer private key. " + err.Error())
	}

	voucherHeader := fdoshared.OwnershipVoucherHeader{
		OVHProtVer:         fdoshared.ProtVer101,
		OVGuid:             newDi.DCGuid,
		OVRvInfo:           ovRVInfo,
		OVDeviceInfo:       newDi.DCDeviceInfo,
		OVPublicKey:        *mfgPublicKey,
		OVDevCertChainHash: &newDi.DCCertificateChainHash,
	}

	// Test
	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_PROT_VERSION {
		voucherHeader.OVHProtVer = fdoshared.ProtVersion(uint16(fdoshared.NewRandomInt(105, 10000)))
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_RVINFO_EMPTY {
		voucherHeader.OVRvInfo = []fdoshared.RendezvousInstrList{}
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_DEVICEINFO_EMPTY {
		voucherHeader.OVDeviceInfo = ""
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_PUBKEY {
		voucherHeader.OVPublicKey = *fdoshared.Conf_RandomTestFuzzPublicKey(voucherHeader.OVPublicKey)
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_CERTCHAIN_HASH {
		var totalBytes []byte
		for _, cert := range newDi.DCCertificateChain {
			totalBytes = append(totalBytes, cert...)
		}

		voucherHeader.OVDevCertChainHash = fdoshared.Conf_RandomTestHashHmac(*voucherHeader.OVDevCertChainHash, totalBytes, nil)
	}

	ovHeaderBytes, err := fdoshared.CborCust.Marshal(voucherHeader)
	if err != nil {
		return nil, errors.New("Error marhaling OVHeader! " + err.Error())
	}

	ovHeaderHmac, err := newDi.UpdateWithManufacturerCred(ovHeaderBytes, *mfgPublicKey)
	if err != nil {
		return nil, err
	}

	oveHdrInfo := append(newDi.DCGuid[:], []byte(newDi.DCDeviceInfo)...)
	oveHdrInfoHash, _ := fdoshared.GenerateFdoHash(oveHdrInfo, newDi.DCHashAlg)

	// Generating OVEntries
	var ovEntryArray []fdoshared.CoseSignature = []fdoshared.CoseSignature{}

	// Test params preparation
	var ovEntriesCount int = fdoshared.NewRandomInt(3, 7)
	var badOvEntryIndex = fdoshared.NewRandomInt(0, ovEntriesCount)

	var prevEntryPrivKey interface{} = mfgPrivateKey
	var prevEntryHash fdoshared.HashOrHmac

	var finalOvEntryPrivateKeyBytes []byte

	var prevEntrySgType fdoshared.DeviceSgType = voucherSgType

	for i := 0; i < ovEntriesCount; i++ {
		if i == 0 {
			headerHmacBytes, err := fdoshared.CborCust.Marshal(ovHeaderHmac)
			if err != nil {
				log.Println("Error generating hash: ", err.Error())
				return nil, err
			}

			if err != nil {
				log.Println("Error generating hash: ", err.Error())
				return nil, err
			}
			prevEntryPayloadBytes := append(ovHeaderBytes, headerHmacBytes...)

			prevEntryHash, err = fdoshared.GenerateFdoHash(prevEntryPayloadBytes, newDi.DCHashAlg)
			if err != nil {
				log.Println("Error generating hash: ", err.Error())
				return nil, err
			}

			// Test
			if i == badOvEntryIndex && fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_PREV_HASH {
				prevEntryHash = *fdoshared.Conf_RandomTestHashHmac(prevEntryHash, oveHdrInfo, []byte{})
			}
		} else {
			prevEntry := ovEntryArray[i-1]
			prevEntryBytes, _ := fdoshared.CborCust.Marshal(prevEntry)
			prevEntryHash, _ = fdoshared.GenerateFdoHash(prevEntryBytes, newDi.DCHashAlg)

			// Test
			if i == badOvEntryIndex && fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_PREV_HASH {
				prevEntryHash = *fdoshared.Conf_RandomTestHashHmac(prevEntryHash, oveHdrInfo, []byte{})
			}
		}

		chosenSgType := voucherSgType
		// Test
		if i == badOvEntryIndex {
			if fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_HDRINFO_HASH {
				oveHdrInfoHash = *fdoshared.Conf_RandomTestHashHmac(oveHdrInfoHash, oveHdrInfo, []byte{})
			}

			if fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_SG_TYPE {
				chosenSgType = fdoshared.Conf_NewRandomSgTypeExcept(chosenSgType)
			}
		}

		newPrivKeyInst, newPrivMashaled, newOvEntry, err := GenerateOvEntry(prevEntryHash, oveHdrInfoHash, prevEntryPrivKey, prevEntrySgType, chosenSgType, fdoTestID)
		if err != nil {
			return nil, err
		}

		prevEntrySgType = chosenSgType

		if i == badOvEntryIndex && fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_SIGNATURE {
			newOvEntry.Signature = fdoshared.Conf_RandomCborBufferFuzzing(newOvEntry.Signature)
		}

		ovEntryArray = append(ovEntryArray, *newOvEntry)

		prevEntryPrivKey = newPrivKeyInst

		if i == ovEntriesCount-1 {
			finalOvEntryPrivateKeyBytes = newPrivMashaled
		}
	}

	voucherInst := fdoshared.OwnershipVoucher{
		OVProtVer:      fdoshared.ProtVer101,
		OVHeaderTag:    ovHeaderBytes,
		OVHeaderHMac:   *ovHeaderHmac,
		OVDevCertChain: &newDi.DCCertificateChain,
		OVEntryArray:   ovEntryArray,
	}

	// Test
	if fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_PROT_VERSION {
		voucherInst.OVProtVer = fdoshared.ProtVersion(uint16(fdoshared.NewRandomInt(105, 10000)))
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_HEADER_BYTES {
		voucherInst.OVHeaderTag = fdoshared.Conf_RandomCborBufferFuzzing(voucherInst.OVHeaderTag)
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_HDR_HMAC {
		voucherInst.OVHeaderHMac = *fdoshared.Conf_RandomTestHashHmac(voucherInst.OVHeaderHMac, ovHeaderBytes, newDi.DCHmacSecret)
	}

	if voucherInst.OVDevCertChain != nil && fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_HDR_HMAC {
		chainTemp := *voucherInst.OVDevCertChain
		leafCert := chainTemp[0]

		chainTemp[0] = chainTemp[1]
		chainTemp[1] = leafCert

		voucherInst.OVDevCertChain = &chainTemp
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_EMPTY_ENTRIES {
		voucherInst.OVEntryArray = []fdoshared.CoseSignature{}
	}

	voucherDBEInst := fdoshared.VoucherDBEntry{
		Voucher:        voucherInst,
		PrivateKeyX509: finalOvEntryPrivateKeyBytes,
	}

	newWDC := fdoshared.DeviceCredAndVoucher{
		VoucherDBEntry:      voucherDBEInst,
		WawDeviceCredential: newDi,
	}

	return &newWDC, err
}

func GenerateAndSaveDeviceCredAndVoucher(deviceCred fdoshared.WawDeviceCredential, voucherSgType fdoshared.DeviceSgType, ovRVInfo []fdoshared.RendezvousInstrList, fdoTestID testcom.FDOTestID) error {
	newdav, err := NewVirtualDeviceAndVoucher(deviceCred, voucherSgType, ovRVInfo, fdoTestID)
	if err != nil {
		return err
	}

	vdandv := *newdav

	// Voucher to PEM
	voucherBytes, err := fdoshared.CborCust.Marshal(vdandv.VoucherDBEntry.Voucher)
	if err != nil {
		return errors.New("Error marshaling voucher bytes. " + err.Error())
	}
	voucherBytesPem := pem.EncodeToMemory(&pem.Block{Type: fdoshared.OWNERSHIP_VOUCHER_PEM_TYPE, Bytes: voucherBytes})

	// LastOVEntry private key to PEM
	ovEntryPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: fdoshared.PRIVATE_KEY_PEM_TYPE, Bytes: vdandv.VoucherDBEntry.PrivateKeyX509})

	voucherFileBytes := append(voucherBytesPem, ovEntryPrivateKeyPem...)

	filetimestamp := time.Now().Format("2006-01-02_15.04.05")
	filename := filetimestamp + hex.EncodeToString(vdandv.WawDeviceCredential.DCGuid[:])

	voucherWriteLocation := fmt.Sprintf("%s/%s.voucher.pem", VOUCHERS_LOCATION, filename)
	err = os.WriteFile(voucherWriteLocation, voucherFileBytes, 0644)
	if err != nil {
		return fmt.Errorf("error saving di \"%s\". %s", voucherWriteLocation, err.Error())
	}

	// Di bytes
	diBytes, err := fdoshared.CborCust.Marshal(vdandv.WawDeviceCredential)
	if err != nil {
		return errors.New("Error marshaling voucher bytes. " + err.Error())
	}

	diBytesPem := pem.EncodeToMemory(&pem.Block{Type: fdoshared.CREDENTIAL_PEM_TYPE, Bytes: diBytes})
	disWriteLocation := fmt.Sprintf("%s/%s.dis.pem", DIS_LOCATION, filename)
	err = os.WriteFile(disWriteLocation, diBytesPem, 0644)
	if err != nil {
		return fmt.Errorf("error saving di \"%s\". %s", disWriteLocation, err.Error())
	}

	log.Println("Successfully generate voucher and di files.")
	log.Println(voucherWriteLocation)
	log.Println(disWriteLocation)

	return nil
}

func MarshalVoucherAndPrivateKey(vdbEntry fdoshared.VoucherDBEntry) ([]byte, error) {
	// Voucher to PEM
	voucherBytes, err := fdoshared.CborCust.Marshal(vdbEntry.Voucher)
	if err != nil {
		return []byte{}, errors.New("Error marshaling voucher bytes. " + err.Error())
	}
	voucherBytesPem := pem.EncodeToMemory(&pem.Block{Type: fdoshared.OWNERSHIP_VOUCHER_PEM_TYPE, Bytes: voucherBytes})

	// LastOVEntry private key to PEM
	ovEntryPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: fdoshared.PRIVATE_KEY_PEM_TYPE, Bytes: vdbEntry.PrivateKeyX509})
	voucherFileBytes := append(voucherBytesPem, ovEntryPrivateKeyPem...)

	return voucherFileBytes, nil

}
