package fdoshared

import (
	"crypto/rand"
	"encoding/pem"
)

type FdoNonce [16]byte

func NewFdoNonce() [16]byte {
	nonceBuff := make([]byte, 16)
	rand.Read(nonceBuff)

	var NonceInst [16]byte
	copy(NonceInst[:], nonceBuff)

	return NonceInst
}

func NewRandomBuffer(size int) []byte {
	nonceBuff := make([]byte, size)
	rand.Read(nonceBuff)

	return nonceBuff
}

type X509CertificateBytes []byte

func (h *X509CertificateBytes) GetPEM() string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: *h,
	}

	pemBytes := pem.EncodeToMemory(block)

	return string(pemBytes)
}
