package fdoshared

type HelloRV30 struct {
	_         struct{} `cbor:",toarray"`
	Guid      FdoGuid
	EASigInfo SigInfo
}

type HelloRVAck31 struct {
	_             struct{} `cbor:",toarray"`
	NonceTO1Proof []byte
	EBSigInfo     SigInfo
}

type ProveToRV32 = CoseSignature

type RVRedirect33 = CoseSignature
