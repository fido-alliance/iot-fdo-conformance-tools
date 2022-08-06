package main

import (
	"bytes"
	"errors"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

var MaxDeviceMessageSize uint16 = 2048
var MaxOwnerServiceInfoSize uint16 = 2048

type To2Requestor struct {
	SrvEntry        SRVEntry
	Credential      fdoshared.WawDeviceCredential
	KexSuiteName    fdoshared.KexSuiteName
	CipherSuiteName fdoshared.CipherSuiteName

	AuthzHeader string
	SessionKey  []byte
	XAKex       []byte
	XBKEXParams fdoshared.KeXParams

	NonceTO2ProveOV60 fdoshared.FdoNonce
	NonceTO2ProveDv61 fdoshared.FdoNonce
	NonceTO2SetupDv64 fdoshared.FdoNonce

	ProveOVHdr61PubKey fdoshared.FdoPublicKey
	OvHmac             fdoshared.HashOrHmac

	Completed60 bool
	Completed62 bool
	Completed64 bool
}

func NewTo2Requestor(srvEntry SRVEntry, credential fdoshared.WawDeviceCredential, kexSuitName fdoshared.KexSuiteName, cipherSuitName fdoshared.CipherSuiteName) To2Requestor {
	return To2Requestor{
		SrvEntry:        srvEntry,
		Credential:      credential,
		KexSuiteName:    kexSuitName,
		CipherSuiteName: cipherSuitName,
	}
}

func (h *To2Requestor) HelloDevice60() (*fdoshared.TO2ProveOVHdrPayload, error) {
	h.NonceTO2ProveOV60 = fdoshared.NewFdoNonce()

	helloDevice60Byte, err := cbor.Marshal(fdoshared.HelloDevice60{
		MaxDeviceMessageSize: MaxDeviceMessageSize,
		Guid:                 h.Credential.DCGuid,
		NonceTO2ProveOV:      h.NonceTO2ProveOV60,
		KexSuiteName:         h.KexSuiteName,
		CipherSuiteName:      h.CipherSuiteName,
		EASigInfo:            h.Credential.DCSigInfo,
	})

	if err != nil {
		return nil, errors.New("HelloDevice60: Error marshaling HelloDevice60. " + err.Error())
	}

	resultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_60_HELLO_DEVICE, helloDevice60Byte, &h.SrvEntry.AccessToken)
	if err != nil {
		return nil, errors.New("HelloDevice60: " + err.Error())
	}

	h.AuthzHeader = authzHeader

	var proveOVHdr61 fdoshared.CoseSignature
	err = cbor.Unmarshal(resultBytes, &proveOVHdr61)
	if err != nil {
		return nil, errors.New("HelloDevice60: Failed to unmarshal HelloRVAck31. " + err.Error())
	}

	// Signature verification
	probableOwnerPubKey := proveOVHdr61.Unprotected.CUPHOwnerPubKey
	err = fdoshared.VerifyCoseSignature(proveOVHdr61, probableOwnerPubKey)
	if err != nil {
		return nil, err
	}

	h.ProveOVHdr61PubKey = probableOwnerPubKey

	var proveOvdrPayload fdoshared.TO2ProveOVHdrPayload
	err = cbor.Unmarshal(proveOVHdr61.Payload, &proveOvdrPayload)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(proveOvdrPayload.NonceTO2ProveOV[:], h.NonceTO2ProveOV60[:]) {
		return nil, errors.New("HelloDevice60: DO returned wrong NonceTO2ProveOV!")
	}

	err = fdoshared.VerifyHMac(proveOvdrPayload.OVHeader, proveOvdrPayload.HMac, h.Credential.DCHmacSecret)
	if err != nil {
		return nil, errors.New("HelloDevice60: Unknown Header HMac!")
	}

	err = fdoshared.VerifyHash(helloDevice60Byte, proveOvdrPayload.HelloDeviceHash)
	if err != nil {
		return nil, errors.New("HelloDevice60: Failed to verify hello device Hash!")
	}

	h.NonceTO2ProveDv61 = proveOVHdr61.Unprotected.CUPHNonce
	h.XAKex = proveOvdrPayload.XAKeyExchange
	h.OvHmac = proveOvdrPayload.HMac

	h.Completed60 = true
	return &proveOvdrPayload, nil
}

func (h *To2Requestor) GetOVNextEntry62(entryNum uint8) (*fdoshared.OVNextEntry63, error) {
	getOvNextEntryBytes, _ := cbor.Marshal(fdoshared.GetOVNextEntry62{
		GetOVNextEntry: entryNum,
	})

	resultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_62_GET_OVNEXTENTRY, getOvNextEntryBytes, &h.AuthzHeader)
	if err != nil {
		return nil, err
	}

	h.AuthzHeader = authzHeader

	var nextEntry fdoshared.OVNextEntry63
	err = cbor.Unmarshal(resultBytes, &nextEntry)
	if err != nil {
		return nil, errors.New("GetOVNextEntry64: Failed to unmarshal OVNextEntry63. " + err.Error())
	}

	return &nextEntry, nil
}

func (h *To2Requestor) ProveDevice64() (*fdoshared.TO2SetupDevicePayload, error) {
	// KEX
	kex, err := fdoshared.GenerateXAKeyExchange(h.KexSuiteName)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error generating XBKeyExchange... " + err.Error())
	}
	h.XBKEXParams = *kex

	// KEX
	newSessionKey, err := fdoshared.DeriveSessionKey(&h.XBKEXParams, h.XAKex, true)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error generating session ShSe... " + err.Error())
	}
	h.SessionKey = newSessionKey

	// Nonce
	h.NonceTO2SetupDv64 = fdoshared.NewFdoNonce()

	// EAT FDO Payload
	to2ProveDevicePayload := fdoshared.TO2ProveDevicePayload{
		XBKeyExchange: h.XBKEXParams.XAKeyExchange,
	}

	// EAT Payload
	eatPayload := fdoshared.EATPayloadBase{
		EatNonce: h.NonceTO2ProveDv61,
		EatFDO:   to2ProveDevicePayload,
	}
	eatPayloadBytes, _ := cbor.Marshal(eatPayload)

	// Private key
	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.Credential.DCPrivateKeyDer)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error extract private key... " + err.Error())
	}

	// EAT and exchange
	proveDevice, err := fdoshared.GenerateCoseSignature(eatPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{EUPHNonce: h.NonceTO2SetupDv64}, privateKeyInst, h.Credential.DCSigInfo.SgType)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error generating device EAT... " + err.Error())

	}
	proveDeviceBytes, _ := cbor.Marshal(proveDevice)

	rawResultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_64_PROVE_DEVICE, proveDeviceBytes, &h.AuthzHeader)
	if err != nil {
		return nil, err
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error decrypting... " + err.Error())
	}

	var setupDevice fdoshared.CoseSignature
	err = cbor.Unmarshal(bodyBytes, &setupDevice)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error decoding SetupDevice65... " + err.Error())
	}

	err = fdoshared.VerifyCoseSignature(setupDevice, h.ProveOVHdr61PubKey)
	if err != nil {
		return nil, err
	}

	var to2SetupDevicePayload fdoshared.TO2SetupDevicePayload
	err = cbor.Unmarshal(setupDevice.Payload, &to2SetupDevicePayload)
	if err != nil {
		return nil, errors.New("ProveDevice64: Error decoding SetupDevice65 Payload... " + err.Error())
	}

	return &to2SetupDevicePayload, nil
}

func (h *To2Requestor) DeviceServiceInfoReady66() (*fdoshared.OwnerServiceInfoReady67, error) {
	deviceSrvInfoReady := fdoshared.DeviceServiceInfoReady66{
		ReplacementHMac:       &h.OvHmac,
		MaxOwnerServiceInfoSz: &MaxOwnerServiceInfoSize,
	}
	deviceSrvInfoReadyBytes, _ := cbor.Marshal(deviceSrvInfoReady)

	deviceSrvInfoReadyBytesEnc, err := fdoshared.AddEncryptionWrapping(deviceSrvInfoReadyBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("DeviceServiceInfoReady66: Error encrypting... " + err.Error())
	}

	rawResultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_66_DEVICE_SERVICE_INFO_READY, deviceSrvInfoReadyBytesEnc, &h.AuthzHeader)
	if err != nil {
		return nil, err
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("DeviceServiceInfoReady66: Error decrypting... " + err.Error())
	}

	var ownerServiceInfoReady67 fdoshared.OwnerServiceInfoReady67
	err = cbor.Unmarshal(bodyBytes, &ownerServiceInfoReady67)
	if err != nil {
		return nil, errors.New("DeviceServiceInfoReady66: Error decoding OwnerServiceInfoReady67... " + err.Error())
	}

	return &ownerServiceInfoReady67, nil
}

func (h *To2Requestor) DeviceServiceInfo68(deviceServiceInfo68 fdoshared.DeviceServiceInfo68) (*fdoshared.OwnerServiceInfo69, error) {

	deviceServiceInfo68Bytes, _ := cbor.Marshal(deviceServiceInfo68)

	deviceServiceInfo68BytesEnc, err := fdoshared.AddEncryptionWrapping(deviceServiceInfo68Bytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("DeviceServiceInfo68: Error encrypting... " + err.Error())
	}

	rawResultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_68_DEVICE_SERVICE_INFO, deviceServiceInfo68BytesEnc, &h.AuthzHeader)
	if err != nil {
		return nil, err
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("DeviceServiceInfo68: Error decrypting... " + err.Error())
	}

	var ownerServiceInfo69 fdoshared.OwnerServiceInfo69
	err = cbor.Unmarshal(bodyBytes, &ownerServiceInfo69)
	if err != nil {
		return nil, errors.New("DeviceServiceInfo68: Error decoding OwnerServiceInfo69... " + err.Error())
	}

	return &ownerServiceInfo69, nil
}

func (h *To2Requestor) Done70() (*fdoshared.Done271, error) {

	done70Bytes, _ := cbor.Marshal(fdoshared.Done70{
		NonceTO2ProveDv: h.NonceTO2ProveDv61,
	})

	done70BytesEnc, err := fdoshared.AddEncryptionWrapping(done70Bytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("Done70: Error encrypting... " + err.Error())
	}

	rawResultBytes, authzHeader, err := SendCborPost(h.SrvEntry, fdoshared.TO2_70_DONE, done70BytesEnc, &h.AuthzHeader)
	if err != nil {
		return nil, err
	}

	h.AuthzHeader = authzHeader

	bodyBytes, err := fdoshared.RemoveEncryptionWrapping(rawResultBytes, h.SessionKey, h.CipherSuiteName)
	if err != nil {
		return nil, errors.New("Done70: Error decrypting... " + err.Error())
	}

	var done271 fdoshared.Done271
	err = cbor.Unmarshal(bodyBytes, &done271)
	if err != nil {
		return nil, errors.New("Done70: Error decoding Done271... " + err.Error())
	}

	if !bytes.Equal(done271.NonceTO2SetupDv[:], h.NonceTO2SetupDv64[:]) {
		return nil, errors.New("Done70: Error verifying Done271. Nonces do not match.")
	}

	return &done271, nil
}
