package fdoshared

type Hello20 struct {
	_ struct{} `cbor:",toarray"`
}

type HelloAck21 struct {
	_            struct{} `cbor:",toarray"`
	NonceTO0Sign FdoNonce
}

type To0d struct {
	_ struct{} `cbor:",toarray"`

	OwnershipVoucher OwnershipVoucher
	WaitSeconds      uint32
	NonceTO0Sign     FdoNonce
}

type To1dBlobPayload struct {
	_            struct{} `cbor:",toarray"`
	To1dRV       []RVTO2AddrEntry
	To1dTo0dHash HashOrHmac // Hash of to0d from
}

type OwnerSign22 struct {
	_    struct{} `cbor:",toarray"`
	To0d []byte
	To1d CoseSignature
}

type AcceptOwner23 struct {
	_           struct{} `cbor:",toarray"`
	WaitSeconds uint32
}
