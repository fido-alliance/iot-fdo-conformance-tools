package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/WebauthnWorks/fdo-device-implementation/fdoshared"
	"github.com/fxamacker/cbor/v2"
)

const DIS_LOCATION string = "./_dis/"
const VOUCHERS_LOCATION string = "./_vouchers/"

func GenerateVoucherKeypair(sgType fdoshared.DeviceSgType) (interface{}, *fdoshared.FdoPublicKey, error) {
	var curve elliptic.Curve
	var pkType fdoshared.FdoPkType

	if sgType == fdoshared.StSECP256R1 {
		curve = elliptic.P256()
		pkType = fdoshared.SECP256R1
	} else if sgType == fdoshared.StSECP384R1 {
		curve = elliptic.P384()
		pkType = fdoshared.SECP384R1
	} else {
		return nil, nil, fmt.Errorf("%d is an unsupported SgType!", sgType)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.New("Error generating new private key. " + err.Error())
	}

	publicKeyPkix, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey)

	return privateKey, &fdoshared.FdoPublicKey{
		PkType: pkType,
		PkEnc:  fdoshared.X509,
		PkBody: publicKeyPkix,
	}, nil
}

func MarshalPrivateKey(privKey interface{}, sgType fdoshared.DeviceSgType) ([]byte, error) {
	if sgType == fdoshared.StSECP256R1 || sgType == fdoshared.StSECP384R1 {
		return x509.MarshalECPrivateKey(privKey.(*ecdsa.PrivateKey))
	} else {
		return []byte{}, fmt.Errorf("%d is an unsupported SgType!", sgType)
	}
}

func GenerateFirstOvEntry(prevEntryHash fdoshared.HashOrHmac, hdrHash fdoshared.HashOrHmac, mfgPrivateKey interface{}, sgType fdoshared.DeviceSgType) ([]byte, *fdoshared.CoseSignature, error) {
	// Generate manufacturer private key.
	newOVEPrivateKey, newOVEPublicKey, err := GenerateVoucherKeypair(sgType)
	if err != nil {
		return []byte{}, nil, err
	}

	ovEntryPayload := fdoshared.OVEntryPayload{
		OVEHashPrevEntry: prevEntryHash,
		OVEHashHdrInfo:   hdrHash,
		OVEExtra:         nil,
		OVEPubKey:        *newOVEPublicKey,
	}

	ovEntryPayloadBytes, err := cbor.Marshal(ovEntryPayload)
	if err != nil {
		return []byte{}, nil, errors.New("Error mashaling OVEntry. " + err.Error())
	}

	protectedHeader := fdoshared.ProtectedHeader{
		Alg: int(sgType),
	}

	ovEntry, err := fdoshared.GenerateCoseSignature(ovEntryPayloadBytes, protectedHeader, fdoshared.UnprotectedHeader{}, mfgPrivateKey, sgType)

	marshaledPrivateKey, err := MarshalPrivateKey(newOVEPrivateKey, sgType)
	if err != nil {
		return []byte{}, nil, errors.New("Error mashaling private key. " + err.Error())
	}

	return marshaledPrivateKey, ovEntry, nil
}

func GenerateVoucher(sgType fdoshared.DeviceSgType) error {
	newDi, err := fdoshared.NewWawDeviceCredential(fdoshared.FDO_HMAC_SHA384)

	// Generate manufacturer private key.
	mfgPrivateKey, mfgPublicKey, err := GenerateVoucherKeypair(sgType)
	if err != nil {
		return errors.New("Error generating new manufacturer private key. " + err.Error())
	}

	voucherHeader := fdoshared.OwnershipVoucherHeader{
		OVHProtVer: fdoshared.ProtVer101,
		OVGuid:     newDi.DCGuid,
		OVRvInfo: []fdoshared.RendezvousInstrList{
			{ // TODO
				fdoshared.RendezvousInstr{
					Key: fdoshared.RVBypass,
				},
			},
		},
		OVDeviceInfo:       newDi.DCDeviceInfo,
		OVPublicKey:        *mfgPublicKey,
		OVDevCertChainHash: &newDi.DCCertificateChainHash,
	}

	ovHeaderBytes, err := cbor.Marshal(voucherHeader)
	if err != nil {
		return errors.New("Error marhaling OVHeader! " + err.Error())
	}

	ovHeaderHmac, err := newDi.UpdateWithManufacturerCred(ovHeaderBytes, *mfgPublicKey)
	if err != nil {
		return err
	}

	// Generate new oventry

	oveHdrInfo := append(newDi.DCGuid[:], []byte(newDi.DCDeviceInfo)...)
	oveHdrInfoHash, _ := fdoshared.GenerateFdoHash(oveHdrInfo, newDi.DCHashAlg)

	headerHmacBytes, _ := cbor.Marshal(ovHeaderHmac)
	prevEntryPayloadBytes := append(ovHeaderBytes, headerHmacBytes...)
	prevEntryHash, _ := fdoshared.GenerateFdoHash(prevEntryPayloadBytes, newDi.DCHashAlg)

	ovEntryPrivateKeyBytes, firstOvEntry, err := GenerateFirstOvEntry(prevEntryHash, oveHdrInfoHash, mfgPrivateKey, sgType)

	// Voucher
	voucherInst := fdoshared.OwnershipVoucher{
		OVProtVer:      fdoshared.ProtVer101,
		OVHeaderTag:    ovHeaderBytes,
		OVHeaderHMac:   *ovHeaderHmac,
		OVDevCertChain: &newDi.DCCertificateChain,
		OVEntryArray: []fdoshared.CoseSignature{
			*firstOvEntry,
		},
	}

	// Voucher to PEM
	voucherBytes, err := cbor.Marshal(voucherInst)
	if err != nil {
		return errors.New("Error marshaling voucher bytes. " + err.Error())
	}
	voucherBytesPem := pem.EncodeToMemory(&pem.Block{Type: "OWNERSHIP VOUCHER", Bytes: voucherBytes})

	// LastOVEntry private key to PEM
	ovEntryPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ovEntryPrivateKeyBytes})

	voucherFileBytes := append(voucherBytesPem, ovEntryPrivateKeyPem...)

	voucherWriteLocation := fmt.Sprintf("%s%s.voucher.pem", VOUCHERS_LOCATION, hex.EncodeToString(newDi.DCGuid[:]))
	err = os.WriteFile(voucherWriteLocation, voucherFileBytes, 0644)
	if err != nil {
		return fmt.Errorf("Error saving di \"%s\". %s", voucherWriteLocation, err.Error())
	}

	// Di bytes
	diBytes, err := cbor.Marshal(newDi)
	if err != nil {
		return errors.New("Error marshaling voucher bytes. " + err.Error())
	}

	diBytesPem := pem.EncodeToMemory(&pem.Block{Type: "WAW FDO DEVICE CREDENTIAL", Bytes: diBytes})
	disWriteLocation := fmt.Sprintf("%s%s.dis.pem", DIS_LOCATION, hex.EncodeToString(newDi.DCGuid[:]))
	err = os.WriteFile(disWriteLocation, diBytesPem, 0644)
	if err != nil {
		return fmt.Errorf("Error saving di \"%s\". %s", disWriteLocation, err.Error())
	}

	return nil
}
