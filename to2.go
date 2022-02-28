package fdoshared

import "reflect"

type HelloDevice60 struct {
	_                    struct{} `cbor:",toarray"`
	MaxDeviceMessageSize uint16
	Guid                 FdoGuid
	NonceTO2ProveOV      []byte
	KexSuiteName         string
	CipherSuiteName      string
	EASigInfo            SigInfo
}

type ProveOVHdr61 = CoseSignature
type TO2ProveOVHdrPayload struct {
	_                   struct{} `cbor:",toarray"`
	OVHeader            []byte
	NumOVEntries        uint8
	HMac                HashOrHmac
	NonceTO2ProveOV     []byte
	EBSigInfo           SigInfo
	XAKeyExchange       XAKeyExchange
	HelloDeviceHash     HashOrHmac
	MaxOwnerMessageSize uint16
} // todo

type GetOVNextEntry62 struct {
	_          struct{} `cbor:",toarray"`
	OVEntryNum uint8
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
	_               struct{}    `cbor:",toarray"`
	RendezvousInfo  interface{} // change
	Guid            FdoGuid
	NonceTO2SetupDv []byte
	Owner2Key       FdoPublicKey
}

type DeviceServiceInfoReady66 struct {
	_                     struct{} `cbor:",toarray"`
	ReplacementHMac       *HashOrHmac
	MaxOwnerServiceInfoSz uint16 // *uint16?
}

type OwnerServiceInfoReady67 struct {
	_                      struct{} `cbor:",toarray"`
	MaxDeviceServiceInfoSz uint16   // *uint16?
}

type DeviceServiceInfo68 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	ServiceInfo       *[]ServiceInfoKV
}

type OwnerServiceInfo69 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       *ServiceInfoKV
}

type ServiceInfoKV struct {
	// ServiceInfoKey []byte // check
	ServiceInfoKey string // check
	// ServiceInfoVal []byte
	ServiceInfoVal reflect.Type
}

type Done70 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2ProveDv []byte
}

type Done271 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2SetupDv []byte
}
