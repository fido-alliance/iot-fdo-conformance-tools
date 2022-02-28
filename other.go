package fdoshared

import (
	"encoding/pem"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type ProtVersion uint16

const (
	ProtVer100 ProtVersion = 100
	ProtVer101 ProtVersion = 101
)

type FdoGuid [16]byte

func (h *FdoGuid) GetFormatted() string {
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

func ComputeOVDevCertChainHash(certs []X509CertificateBytes, hashType HashType) (HashOrHmac, error) {
	var totalBytes []byte
	for _, cert := range certs {
		totalBytes = append(totalBytes, cert...)
	}

	return GenerateFdoHash(totalBytes, hashType)
}

func VerifyOVEntries(voucherInst OwnershipVoucher) error {
	var lastOVEntry CoseSignature
	for i, OVEntry := range voucherInst.OVEntryArray {
		var OVEntryPayload OVEntryPayload
		err := cbor.Unmarshal(OVEntry.Payload, &OVEntryPayload)
		if err != nil {
			return errors.New("Error Verifying OVEntries" + err.Error())
		}
		if i == 0 {
			headerHmacBytes, _ := cbor.Marshal(voucherInst.OVHeaderHMac)
			firstEntryHashContents := append(voucherInst.OVHeaderTag, headerHmacBytes...)
			verifiedHash, err := VerifyHash(firstEntryHashContents, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Internal Server Error" + err.Error())
			}
			if !verifiedHash {
				return errors.New("Could not verify hash of entry 0" + err.Error())
			}
		} else {
			lastOVEntryBytes, err := cbor.Marshal(lastOVEntry)
			if err != nil {
				return errors.New("Error Verifying OVEntries" + err.Error())
			}
			verifiedHash, err := VerifyHash(lastOVEntryBytes, OVEntryPayload.OVEHashPrevEntry)
			if err != nil {
				return errors.New("Internal Server Error" + err.Error())
			}
			if !verifiedHash {
				return errors.New("Could not verify hash (Entry)" + err.Error())
			}
		}
		lastOVEntry = OVEntry
	}
	return nil
}
