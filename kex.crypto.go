package fdoshared

type KexSuiteName string

const (
	ECDH256 KexSuiteName = "ECDH256"
	ECDH384 KexSuiteName = "ECDH384"
	// ProtHTTP  KexSuiteName = 3
	// ProtCoAP  KexSuiteName = 4
	// ProtHTTPS KexSuiteName = 5
	// ProtCoAPS KexSuiteName = 6
)

type XAKeyExchange []byte
type KeyExchangeComponents struct {
	x []byte
	y []byte
	r []byte
}
