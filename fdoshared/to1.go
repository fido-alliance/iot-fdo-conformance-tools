package fdoshared

type HelloRV30 struct {
	_         struct{} `cbor:",toarray"`
	Guid      FDOGuid
	EASigInfo SigInfo
}

type HelloRVAck31 struct {
	_             struct{} `cbor:",toarray"`
	NonceTO1Proof []byte
	EBSigInfo     SigInfo
}

type ProveToRV32 struct {
	_       struct{} `cbor:",toarray"`
	EAToken CoseSignature
}

type RVRedirect33 struct {
	_          struct{} `cbor:",toarray"`
	RVRedirect CoseSignature
}
