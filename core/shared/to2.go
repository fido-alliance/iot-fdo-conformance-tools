package fdoshared

import "fmt"

type HelloDevice60 struct {
	_                    struct{} `cbor:",toarray"`
	MaxDeviceMessageSize uint16
	Guid                 FdoGuid
	NonceTO2ProveOV      FdoNonce
	KexSuiteName         KexSuiteName
	CipherSuiteName      CipherSuiteName
	EASigInfo            SigInfo
}

type TO2ProveOVHdrPayload struct {
	_                   struct{} `cbor:",toarray"`
	OVHeader            []byte
	NumOVEntries        uint8
	HMac                HashOrHmac
	NonceTO2ProveOV     FdoNonce
	EBSigInfo           SigInfo
	XAKeyExchange       []byte
	HelloDeviceHash     HashOrHmac
	MaxOwnerMessageSize uint16
}

type GetOVNextEntry62 struct {
	_              struct{} `cbor:",toarray"`
	GetOVNextEntry uint8
}

type OVNextEntry63 struct {
	_          struct{} `cbor:",toarray"`
	OVEntryNum uint8
	OVEntry    CoseSignature
}

type ProveDevice64 = CoseSignature // EAToken
// TO2ProveDevicePayload  defined in other file

type SetupDevice65 = CoseSignature

type TO2SetupDevicePayload struct {
	_                    struct{} `cbor:",toarray"`
	RendezvousInfo       RendezvousInfo
	ReplacementGuid      FdoGuid
	NonceTO2SetupDv      FdoNonce
	ReplacementOwner2Key FdoPublicKey
}

func (h *TO2SetupDevicePayload) Validate() error {
	if len(h.RendezvousInfo) == 0 {
		return fmt.Errorf("TO2SetupDevicePayload: RendezvousServerInfo is empty")
	}

	return nil
}

func (h *TO2SetupDevicePayload) IsCredentialReuse(oldGuid FdoGuid) bool {
	return h.ReplacementGuid.Equals(oldGuid)
}

type DeviceServiceInfoReady66 struct {
	_                     struct{} `cbor:",toarray"`
	ReplacementHMac       *HashOrHmac
	MaxOwnerServiceInfoSz *uint16
}

type OwnerServiceInfoReady67 struct {
	_                      struct{} `cbor:",toarray"`
	MaxDeviceServiceInfoSz *uint16
}

type DeviceServiceInfo68 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	ServiceInfo       []ServiceInfoKV
}

type OwnerServiceInfo69 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []ServiceInfoKV
}

type Done70 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2ProveDv FdoNonce
}

type Done271 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2SetupDv FdoNonce
}
