package fdoshared

type HelloDevice60 struct {
	_                    struct{} `cbor:",toarray"`
	MaxDeviceMessageSize uint16
	Guid                 FdoGuid
	NonceTO2ProveOV      []byte
	kexSuiteName         string
	cipherSuiteName      string
	EASigInfo            SigInfo
}

type ProveOVHdr61 = CoseSignature
type TO2ProveOVHdrPayload struct {
	OVHeader            []byte
	NumOVEntries        uint8
	HMac                HashOrHmac
	NonceTO2ProveOV     []byte
	EBSigInfo           SigInfo
	XAKeyExchange       string // XAKeyExchange
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

type SetupDevice65 = CoseSignature

type DeviceServiceInfoReady66 struct {
	_                     struct{} `cbor:",toarray"`
	ReplacementHMac       HashOrHmac
	maxOwnerServiceInfoSz uint16
}

type OwnerServiceInfoReady67 struct {
	_                      struct{} `cbor:",toarray"`
	maxDeviceServiceInfoSz uint16
}

type DeviceServiceInfo68 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	ServiceInfo       ServiceInfoKV
}

type OwnerServiceInfo69 struct {
	_                 struct{} `cbor:",toarray"`
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       ServiceInfoKV
}

type ServiceInfoKV struct {
	ServiceInfoKey []byte // check
	ServiceInfoVal []byte
}

type Done70 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2ProveDv []byte
}

type Done271 struct {
	_               struct{} `cbor:",toarray"`
	NonceTO2SetupDv []byte
}
