package to0

import (
	"errors"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/fxamacker/cbor/v2"
)

func (h *To0Requestor) OwnerSign22(nonceTO0Sign fdoshared.FdoNonce) (*fdoshared.AcceptOwner23, error) {
	// TO0D
	var to0d fdoshared.To0d = fdoshared.To0d{
		OwnershipVoucher: h.voucherDBEntry.Voucher,
		WaitSeconds:      ServerWaitSeconds,
		NonceTO0Sign:     nonceTO0Sign,
	}
	to0dBytes, err := cbor.Marshal(to0d)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling To0d. " + err.Error())
	}

	deviceHashAlg := fdoshared.HmacToHashAlg[h.voucherDBEntry.Voucher.OVHeaderHMac.Type]
	to0dHash, err := fdoshared.GenerateFdoHash(to0dBytes, deviceHashAlg)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error generating to0dHash. " + err.Error())
	}

	// TO1D Payload
	// TODO
	var localostIPBytes fdoshared.FdoIPAddress = []byte{127, 0, 0, 1}

	var to1dPayload fdoshared.To1dBlobPayload = fdoshared.To1dBlobPayload{
		To1dRV: []fdoshared.RVTO2AddrEntry{
			{
				RVIP:       &localostIPBytes,
				RVPort:     8084,
				RVProtocol: fdoshared.ProtHTTP,
			},
		},
		To1dTo0dHash: to0dHash,
	}

	to1dPayloadBytes, err := cbor.Marshal(to1dPayload)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling To1dPayload. " + err.Error())
	}

	// TO1D CoseSignature
	lastOvEntryPubKey, err := h.voucherDBEntry.Voucher.GetFinalOwnerPublicKey()
	if err != nil {
		return nil, errors.New("OwnerSign22: Error extracting last OVEntry public key. " + err.Error())
	}

	privateKeyInst, err := fdoshared.ExtractPrivateKey(h.voucherDBEntry.PrivateKeyX509)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error extracting private key. " + err.Error())
	}

	sgType, err := fdoshared.GetDeviceSgType(lastOvEntryPubKey.PkType, deviceHashAlg)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error getting device SgType. " + err.Error())
	}

	to1d, err := fdoshared.GenerateCoseSignature(to1dPayloadBytes, fdoshared.ProtectedHeader{}, fdoshared.UnprotectedHeader{}, privateKeyInst, sgType)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error generating To1D COSE signature. " + err.Error())
	}

	var ownerSign fdoshared.OwnerSign22 = fdoshared.OwnerSign22{
		To0d: to0dBytes,
		To1d: *to1d,
	}
	ownerSign22Bytes, err := cbor.Marshal(ownerSign)
	if err != nil {
		return nil, errors.New("OwnerSign22: Error marshaling OwnerSign22. " + err.Error())
	}

	resultBytes, authzHeader, _, err := SendCborPost(h.rvEntry, fdoshared.TO0_22_OWNER_SIGN, ownerSign22Bytes, &h.authzHeader)
	if err != nil {
		return nil, errors.New("OwnerSign22: " + err.Error())
	}

	h.authzHeader = authzHeader

	var acceptOwner23 fdoshared.AcceptOwner23
	err = cbor.Unmarshal(resultBytes, &acceptOwner23)
	if err != nil {
		return nil, errors.New("OwnerSign22: Failed to unmarshal AcceptOwner23. " + err.Error())
	}

	return &acceptOwner23, nil
}
