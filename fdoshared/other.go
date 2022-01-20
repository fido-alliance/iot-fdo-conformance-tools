package fdoshared

import (
	"encoding/pem"

	"github.com/google/uuid"
)

type ProtVersion uint16

const (
	ProtVer100 ProtVersion = 100
	ProtVer101 ProtVersion = 101
)

type FDOGuid [16]byte

func (h *FDOGuid) GetFormatted() string {
	uuidBytes := h[:]
	uuidInst, _ := uuid.ParseBytes(uuidBytes)

	return uuidInst.String()
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

// timestamp = null / UTCStr / UTCInt / TIME_T
// UTCStr = #6.0(tstr)
// UTCInt = #6.1(uint)
// TIMET  = #6.1(uint)
type FdoTimestamp interface{} // TODO

const IPv6Len = 16
const IPv4Len = 4

type FdoIPAddress []byte

func (h FdoIPAddress) IsValid() bool {
	if len(h) != IPv4Len && len(h) != IPv6Len {
		return false
	}

	return true
}

func (h FdoIPAddress) ToString() string {
	// TODO
	return ""
}

// RVTO2AddrEntry = [
//     RVIP: IPAddress / null,       ;; IP address where Owner is waiting for TO2
//     RVDNS: DNSAddress / null,     ;; DNS address where Owner is waiting for TO2
//     RVPort: Port,                 ;; TCP/UDP port to go with above
//     RVProtocol: TransportProtocol ;; Protocol, to go with above
// ]

type TransportProtocol uint16

const (
	ProtTCP   TransportProtocol = 1
	ProtTLS   TransportProtocol = 2
	ProtHTTP  TransportProtocol = 3
	ProtCoAP  TransportProtocol = 4
	ProtHTTPS TransportProtocol = 5
	ProtCoAPS TransportProtocol = 6
)

type RVTO2AddrEntry struct {
	_ struct{} `cbor:",toarray"`

	RVIP       *FdoIPAddress
	RVDNS      *string
	RVPort     uint16
	RVProtocol TransportProtocol
}
