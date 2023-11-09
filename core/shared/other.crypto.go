package fdoshared

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
)

type FdoNonce [16]byte

func (h *FdoNonce) Equals(other FdoNonce) bool {
	return bytes.Equal(h[:], other[:])
}

func NewFdoNonce() FdoNonce {
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

func NewRandomString(size int) string {
	var randBuffer = NewRandomBuffer(size)
	var randString = base64.RawURLEncoding.EncodeToString(randBuffer)

	return randString[0:size]
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

func GetIntRef(intnum int) *int {
	return &intnum
}
