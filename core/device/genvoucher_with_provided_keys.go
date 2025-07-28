package device

import (
	"errors"
	"log"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
)

func NewVirtualDeviceAndVoucherWithKeys(
	newDi fdoshared.WawDeviceCredential,
	ownerPrivKey any,
	ownerPubKey *fdoshared.FdoPublicKey,
	sgType fdoshared.SgType,
	ovRVInfo fdoshared.RendezvousInfo,
	fdoTestID testcom.FDOTestID,
) (*fdoshared.DeviceCredAndVoucher, error) {
	negotiatedHashHmac := fdoshared.NegotiateHashHmacTypes(newDi.DCSigInfo.SgType, sgType)

	newDi.UpdateToNewHashHmacTypes(negotiatedHashHmac)

	// Generate manufacturer private key.
	mfgPrivateKey, mfgPublicKey, err := fdoshared.GenerateVoucherKeypair(sgType)
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

	// Tests
	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_PROT_VERSION {
		voucherHeader.OVHProtVer = fdoshared.ProtVersion(uint16(fdoshared.NewRandomInt(105, 10000)))
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_HEADER_BAD_RVINFO_EMPTY {
		voucherHeader.OVRvInfo = fdoshared.RendezvousInfo{}
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
	badOvEntryIndex := fdoshared.NewRandomInt(0, ovEntriesCount)

	var prevEntryPrivKey interface{} = mfgPrivateKey
	var prevEntryHash fdoshared.HashOrHmac

	var finalOvEntryPrivateKeyBytes []byte

	var prevEntrySgType fdoshared.SgType = sgType

	for i := 0; i < ovEntriesCount; i++ {
		if i == 0 {
			headerHmacBytes, err := fdoshared.CborCust.Marshal(ovHeaderHmac)
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

		chosenSgType := sgType

		var (
			privKey    interface{}
			newOvEntry *fdoshared.CoseSignature
		)

		isFinalEntry := i == ovEntriesCount-1
		if isFinalEntry {
			var marshalledPrivKey []byte
			privKey, marshalledPrivKey, newOvEntry, err = GenerateOvEntryWithKeys(
				prevEntryHash,
				oveHdrInfoHash,
				ownerPrivKey,
				ownerPubKey,
				prevEntryPrivKey,
				prevEntrySgType,
				chosenSgType,
				fdoTestID,
			)

			finalOvEntryPrivateKeyBytes = marshalledPrivKey
		} else {
			privKey, _, newOvEntry, err = GenerateOvEntry(prevEntryHash, oveHdrInfoHash, prevEntryPrivKey, prevEntrySgType, chosenSgType, fdoTestID)
			if err != nil {
				return nil, err
			}
		}

		prevEntrySgType = chosenSgType

		if i == badOvEntryIndex && fdoTestID == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_SIGNATURE {
			newOvEntry.Signature = fdoshared.Conf_RandomCborBufferFuzzing(newOvEntry.Signature)
		}

		ovEntryArray = append(ovEntryArray, *newOvEntry)

		prevEntryPrivKey = privKey
	}

	voucherInst := fdoshared.OwnershipVoucher{
		OVProtVer:      fdoshared.ProtVer101,
		OVHeaderTag:    ovHeaderBytes,
		OVHeaderHMac:   *ovHeaderHmac,
		OVDevCertChain: &newDi.DCCertificateChain,
		OVEntryArray:   ovEntryArray,
	}

	if fdoTestID == testcom.FIDO_TEST_VOUCHER_BAD_CHAIN {
		fakeCert := fdoshared.Conf_RandomCborBufferFuzzing(newDi.DCCertificateChain[0])
		fakeCertChain := append(*voucherInst.OVDevCertChain, fakeCert)
		voucherInst.OVDevCertChain = &fakeCertChain
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

	voucherDBEInst := fdoshared.VoucherDBEntry{
		Voucher:        voucherInst,
		SgType:         sgType,
		PrivateKeyX509: finalOvEntryPrivateKeyBytes,
	}

	newWDC := fdoshared.DeviceCredAndVoucher{
		VoucherDBEntry:      voucherDBEInst,
		WawDeviceCredential: newDi,
	}

	return &newWDC, err
}

func GenerateOvEntryWithKeys(
	prevEntryHash fdoshared.HashOrHmac,
	hdrHash fdoshared.HashOrHmac,
	newPrivKey any,
	newPubKey *fdoshared.FdoPublicKey,
	prevPrivKey any,
	prevEntrySgType fdoshared.SgType,
	newEntrySgType fdoshared.SgType,
	testId testcom.FDOTestID,
) (interface{}, []byte, *fdoshared.CoseSignature, error) {
	if testId == testcom.FIDO_TEST_VOUCHER_ENTRY_BAD_PUBKEY {
		newPubKey = fdoshared.Conf_RandomTestFuzzPublicKey(*newPubKey)
	}

	ovEntryPayload := fdoshared.OVEntryPayload{
		OVEHashPrevEntry: prevEntryHash,
		OVEHashHdrInfo:   hdrHash,
		OVEExtra:         nil,
		OVEPubKey:        *newPubKey,
	}

	ovEntryPayloadBytes, err := fdoshared.CborCust.Marshal(ovEntryPayload)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error marshaling OVEntry. " + err.Error())
	}

	protectedHeader := fdoshared.ProtectedHeader{
		Alg: fdoshared.GetIntRef(int(prevEntrySgType)),
	}

	ovEntry, err := fdoshared.GenerateCoseSignature(ovEntryPayloadBytes, protectedHeader, fdoshared.UnprotectedHeader{}, prevPrivKey, prevEntrySgType)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error generating OVEntry. " + err.Error())
	}

	marshaledPrivateKey, err := fdoshared.MarshalPrivateKey(newPrivKey, newEntrySgType)
	if err != nil {
		return nil, []byte{}, nil, errors.New("Error marshaling private key. " + err.Error())
	}

	return newPrivKey, marshaledPrivateKey, ovEntry, nil
}
