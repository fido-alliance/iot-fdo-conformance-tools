package fdoshared

type HelloRV30 struct {
	_         struct{} `cbor:",toarray"`
	Guid      FdoGuid
	EASigInfo SigInfo
}

type HelloRVAck31 struct {
	_             struct{} `cbor:",toarray"`
	NonceTO1Proof FdoNonce
	EBSigInfo     SigInfo
}

type RVRedirect33 struct {
	_          struct{} `cbor:",toarray"`
	RVRedirect CoseSignature
}
