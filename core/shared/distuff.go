package fdoshared

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type WawDeviceCredential struct {
	_ struct{} `cbor:",toarray"`

	DCProtVer ProtVersion

	DCHmacSecret []byte
	DCHmacAlg    HashType
	DCHashAlg    HashType

	DCDeviceInfo string
	DCGuid       FdoGuid
	DCPubKeyHash HashOrHmac

	DCPrivateKeyDer        []byte
	DCCertificateChain     []X509CertificateBytes
	DCCertificateChainHash HashOrHmac
	DCSigInfo              SigInfo
}

func (h *WawDeviceCredential) UpdatedToNewHashHmac(newSgInfo SgTypeInfo) {
	h.DCHashAlg = newSgInfo.HashType
	h.DCHmacAlg = newSgInfo.HmacType

	newDcCertificateChainHash, _ := ComputeOVDevCertChainHash(h.DCCertificateChain, HmacToHashAlg[h.DCHmacAlg])
	h.DCCertificateChainHash = newDcCertificateChainHash

	h.DCHmacSecret = NewHmacKey(h.DCHmacAlg)
}

func (h *WawDeviceCredential) UpdateWithManufacturerCred(ovHeader []byte, ovPubKey FdoPublicKey) (*HashOrHmac, error) {
	pubKeyBytes, err := CborCust.Marshal(ovPubKey)
	if err != nil {
		return nil, errors.New("error encoding manufacturer public key")
	}

	pubKeyHash, _ := GenerateFdoHash(pubKeyBytes, h.DCHashAlg)
	h.DCPubKeyHash = pubKeyHash

	ovHmac, _ := GenerateFdoHmac(ovHeader, h.DCHmacAlg, h.DCHmacSecret)
	return &ovHmac, nil
}

// BUG: the problem is with these certificates

const TestRootCert string = `
-----BEGIN CERTIFICATE-----
MIIFzTCCA7WgAwIBAgIUQTMpoTm7STUMuELyfpWLShiM+dYwDQYJKoZIhvcNAQEL
BQAwdTEWMBQGA1UEAwwNRkRPIFRFU1QgUk9PVDEiMCAGCSqGSIb3DQEJARYTaW5m
b0B3ZWJhdXRobi53b3JrczEXMBUGA1UECgwOV2ViYXV0aG4gV29ya3MxCzAJBgNV
BAYTAk5aMREwDwYDVQQHDAhUYXVyYW5nYTAgFw0yNTA2MTgyMDQ2MDJaGA8yMDUy
MTEwMzIwNDYwMlowdTEWMBQGA1UEAwwNRkRPIFRFU1QgUk9PVDEiMCAGCSqGSIb3
DQEJARYTaW5mb0B3ZWJhdXRobi53b3JrczEXMBUGA1UECgwOV2ViYXV0aG4gV29y
a3MxCzAJBgNVBAYTAk5aMREwDwYDVQQHDAhUYXVyYW5nYTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBANGilmWMgNcaSEevXRhW4p2unN9O+RydaSiW/SwN
/2YHT8HMiSobiO55loVWG6tSEoyRsU6PyfIth278T1sqk/79t/AU0IX+0SZOGtPH
rkRtCvQDBa8HKekIYMufc1bubsYbHiucslZ84sWLF/6xW453dEGC5EOvrwmhpxOY
9bo1mFD1sbxORtOKJnholyLrU2zjecYV7/4KHVsc5uGW0sn8rFIUL5mjwQZMnBa3
WBoaaAxvxsEnGWYXIurHhVah+yOA60ce4f5QXn8mDsQtqxXjQwm6JJy6Hr4vGgBh
GCVL2HcJANKOSZDkgGFG3U/ISL2HGM/HpoxUjjgyI1f4WxpvacyFd3MdquZQRO5D
C/aMo4QwQIBZ5Yoe0qF0NTBqk3dVRm5jZeWxl9golKE7/kMr814XDtDNPVF9Hr3P
cQnjaqntCwdCL6fH2paZw6kRUxpkzU95gdhV5Vl3la0gPqhxkmqTGOvWSPxNg0g+
89J4q/357yXXB3n7emPy2pO1PIQuY+DuqxikhkSL2U7HePi6TclsJjFLEo7ISlxY
7RBNED1ZpSt0egemxkjh6orQfc4OcQM9kcEmONHHM966s9DSqBtEuDo7RAIuhjq3
dxnYcGJftTD2wFA+lpv9SFP0+GNlZ/GrVc4zGlZrsTmh3WGcvgd4jzPUmlIG2ywQ
8a3FAgMBAAGjUzBRMB0GA1UdDgQWBBS3POb2usec0jYdJGZxFEBC+Noj+zAfBgNV
HSMEGDAWgBS3POb2usec0jYdJGZxFEBC+Noj+zAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQATxhuhC5eRUtWR5ou27fpF4XLq2l5W2dLwOXPeyj2s
bk+7ccY4xvtFirHZX/u7xShtF1/8+GIRs1om2sAFWDXqroBh41Lx2f+MZkyZO3nb
a04JWfXbTEOCzpbWAzmO7lGhEq5vO2Nk9P+kUjEVwKv3rOzzIlZDCJoni6At3Ie+
NqXWDkAgJlzdXOpJjFb+RkkTg8UGfghRET25lCV2Jdsnow4az4ZkJYX5PqTrJ02V
b9mGvHBOxImLWy8zs4jXa0+0f5sGQ52feOauDVBUGs8zdTUQXgnT5sEyQvWJoUKT
iNi71oqOzoMDiohHSA7R4/EBGr4Ifo81i0v2/ZZ+Q509WJnLR47m8xs5Tw5aydDk
m9FiNI6a1aEqQvYctCB1fBi1j9v6C36fXG7Di8ubBE4YhkCyXWcbvO6oheuv2/vF
H3odp1sN4orwbqcm9RzbDbiOb5lSnGvypARweDxg8haXJMykn54KQ0UNlDfUYYOT
m4IihjJEm2QmZ3Th+10MGOwKt0Cexu3B5SYwXEco2udoMAb/DzqHo4taH9+pKRbP
4VbCcLxvhQEHVjTL84qnQ9dNctbPUrwwdLi08UIXlaTpzX9FEsXG1aRaKQOmRqG5
fRUbyZQxZil93EuJLs7oH8pADfswGV+rBOvEAp4RVvCYzYDG92oi5H1xme+6Fp4N
mA==
-----END CERTIFICATE-----
`

const TestRootKey string = `
-----BEGIN PRIVATE KEY-----
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
8hHh8PLC/O4C0vbFcdK+Ei3I6b0iJao=
-----END PRIVATE KEY-----
`

const TestIntermediateCert string = `
-----BEGIN CERTIFICATE-----
MIID9DCCAdygAwIBAgIBAjANBgkqhkiG9w0BAQsFADB1MRYwFAYDVQQDDA1GRE8g
VEVTVCBST09UMSIwIAYJKoZIhvcNAQkBFhNpbmZvQHdlYmF1dGhuLndvcmtzMRcw
FQYDVQQKDA5XZWJhdXRobiBXb3JrczELMAkGA1UEBhMCTloxETAPBgNVBAcMCFRh
dXJhbmdhMCAXDTI1MDYxODIwNDYwMloYDzIwNTIxMTAzMjA0NjAyWjB9MR4wHAYD
VQQDDBVGRE8gVEVTVCBJTlRFUk1FRElBVEUxIjAgBgkqhkiG9w0BCQEWE2luZm9A
d2ViYXV0aG4ud29ya3MxFzAVBgNVBAoMDldlYmF1dGhuIFdvcmtzMQswCQYDVQQG
EwJOWjERMA8GA1UEBwwIVGF1cmFuZ2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQ6QQ5YQb0X2fFkN53obsaXrq9X7hC+w//NhFq7icd1CjWRND4T9XiO7g5Ro8zD
ahsuC65sQjLa6WhKBki40WjUo1AwTjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBT9
A69qpeINC9NRJg7gAV8ZfT3KSjAfBgNVHSMEGDAWgBS3POb2usec0jYdJGZxFEBC
+Noj+zANBgkqhkiG9w0BAQsFAAOCAgEAZojP4RDPjZnJoND2pymvMOyvRAjleagx
W64/mcB1OG+t7sNQkreDc+CiPDjrM0wsSnwMF+aIiDxBjC13Uoe7/QHmgapGxr6V
IbUFzyAHFprId5eWMtO12k13shJXq7QXhRhZSQs8xgynA9VvzUbj9rWIE/Un6TED
I2A614IPHZ4+kqK+wd6og+j3GzbrlNyDKp0CHchtjKdpaSWlTWaiSpN46hY5vguI
4Zz/Nie2wOJx8yCiIkymjqWmHg1bQ+vfsEDs3T2rDSok+XAd+aRp0mCIlrPiklHt
bNWRBo7p9eLwfHzi04GZgQZ1mGWCmYj1ikUyqBRRtdGFuPTS9TtiNYy6C+vY5KgK
zr4epFOC2lxkkXc5OlDTeFlxlURbbCpOIVwOEf3k+kFQxEypOJQ74rsMLyockyn+
mD4naSIsiX1G9bwE0Nn/7tcp/4O735waL9hFHBEGai1s9EpcKq5LEl+T8iRPo6FY
swwzl/G3ymPM0nmFJLa64qY+toFnsAi5Iacvx3KDaVQ+n63WKwP44BmUexnXSfRa
3j2HPpW8EnIoFjplxXEvRteMVC89OkW0heyuD9630gqoU0gH4zq5wQlza+3SC80c
hbogCFSqFoxJL7RIyLaq/YR3EmM4Wc6HPp+JOTrwaX04LxdZheRxSwiFZqSOE3pe
Mhbr7+djEuw=
-----END CERTIFICATE-----
`

const TestIntermediateKey string = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILHyXgSdIBzrmMuANjrrbD5oieS5oWcZhh9OTqKHANxuoAoGCCqGSM49
AwEHoUQDQgAEOkEOWEG9F9nxZDed6G7Gl66vV+4QvsP/zYRau4nHdQo1kTQ+E/V4
ju4OUaPMw2obLguubEIy2uloSgZIuNFo1A==
-----END EC PRIVATE KEY-----
`

func CastPublicFromPrivate(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func NewWawDeviceCredential(sgType DeviceSgType) (*WawDeviceCredential, error) {
	if sgType != StSECP256R1 && sgType != StSECP384R1 {
		return nil, errors.New("for device attestation only SECP256R1 and SECP384R1 are supported")
	}

	newGuid := NewFdoGuid_FIDO()

	// Generate certificate chain
	rootCert, _ := pem.Decode([]byte(TestRootCert))
	intermCert, _ := pem.Decode([]byte(TestIntermediateCert))
	intermKey, _ := pem.Decode([]byte(TestIntermediateKey))

	intermCertInst, err := x509.ParseCertificate(intermCert.Bytes)
	if err != nil {
		return nil, errors.New("Error decoding intermediate certificate. " + err.Error())
	}

	intermPrivKey, err := x509.ParseECPrivateKey(intermKey.Bytes)
	if err != nil {
		return nil, errors.New("Error decoding intermediate key. " + err.Error())
	}

	serialNumber := new(big.Int)
	serialNumber.SetString(newGuid.GetFormattedHex(), 16)
	newCertificate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("WAW FDO VIRTUAL TEST %X WAW", newGuid.GetFormatted()),
			Organization: []string{"FIDO Alliance"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
	}

	newPrivateKeyInst, _, err := GenerateVoucherKeypair(sgType)
	if err != nil {
		return nil, err
	}

	newCertBytes, err := x509.CreateCertificate(rand.Reader, newCertificate, intermCertInst, CastPublicFromPrivate(newPrivateKeyInst), intermPrivKey)
	if err != nil {
		return nil, errors.New("error generating new x509 certificate! " + err.Error())
	}

	marshaledPrivateKey, err := MarshalPrivateKey(newPrivateKeyInst, sgType)
	if err != nil {
		return nil, errors.New("error mashaling private key. " + err.Error())
	}

	dcCertificateChain := []X509CertificateBytes{
		newCertBytes, intermCert.Bytes, rootCert.Bytes,
	}

	sgTypeInfo, ok := SgTypeInfoMap[sgType]
	if !ok {
		return nil, errors.New("unknown sgType")
	}

	dcCertificateChainHash, _ := ComputeOVDevCertChainHash(dcCertificateChain, HmacToHashAlg[sgTypeInfo.HmacType])

	dcSigInfo := SigInfo{
		SgType: sgType,
		Info:   []byte("fido-fdo-virtual-device"),
	}

	var hmacSecret []byte = NewHmacKey(sgTypeInfo.HmacType)

	return &WawDeviceCredential{
		DCProtVer:    ProtVer101,
		DCHmacSecret: hmacSecret,

		DCCertificateChain:     dcCertificateChain,
		DCCertificateChainHash: dcCertificateChainHash,

		DCPrivateKeyDer: marshaledPrivateKey,

		DCGuid:    newGuid,
		DCSigInfo: dcSigInfo,

		DCHmacAlg: sgTypeInfo.HmacType,
		DCHashAlg: sgTypeInfo.HashType,

		DCDeviceInfo: "I am a virtual FIDO Alliance device!",
	}, nil
}

func RandomSgType() DeviceSgType {
	for {
		randLoc := NewRandomInt(0, len(SgTypeList)-1)

		if SgTypeList[randLoc] != StEPID10 && SgTypeList[randLoc] != StEPID11 {
			return SgTypeList[randLoc]
		}
	}
}

func RandomDeviceSgType() DeviceSgType {
	for {
		randLoc := NewRandomInt(0, len(DeviceSgTypeList)-1)

		if DeviceSgTypeList[randLoc] != StEPID10 && DeviceSgTypeList[randLoc] != StEPID11 {
			return DeviceSgTypeList[randLoc]
		}
	}
}
