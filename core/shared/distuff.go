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
	DCRVInfo     []RendezvousInstrList
	DCPubKeyHash HashOrHmac

	DCPrivateKeyDer        []byte
	DCCertificateChain     []X509CertificateBytes
	DCCertificateChainHash HashOrHmac
	DCSigInfo              SigInfo
}

const TestRootCert string = `-----BEGIN CERTIFICATE-----
MIIFZjCCA04CCQCtoxts6anDEzANBgkqhkiG9w0BAQsFADB1MRYwFAYDVQQDDA1G
RE8gVEVTVCBST09UMSIwIAYJKoZIhvcNAQkBFhNpbmZvQHdlYmF1dGhuLndvcmtz
MRcwFQYDVQQKDA5XZWJhdXRobiBXb3JrczELMAkGA1UEBhMCTloxETAPBgNVBAcM
CFRhdXJhbmdhMB4XDTIyMDEyMzE2MDIyOVoXDTQ5MDYxMDE2MDIyOVowdTEWMBQG
A1UEAwwNRkRPIFRFU1QgUk9PVDEiMCAGCSqGSIb3DQEJARYTaW5mb0B3ZWJhdXRo
bi53b3JrczEXMBUGA1UECgwOV2ViYXV0aG4gV29ya3MxCzAJBgNVBAYTAk5aMREw
DwYDVQQHDAhUYXVyYW5nYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AN0i86TTaZOf66eWGvj5uNBco3n6MLBKfZOByCPPYXRKUF+Wx6xVy/jcNAZYBRgw
HS5IXEZi797emrJJVO1TudgNSbfXFJCzMN31NPHuiZkmiT0bRiWgbO9zVqzvxi+A
cuwm/rZe11oF+QMSxa32OsA7krLxrDNH7xNHuZEbnZbuU7F4bjCLAyc/12CBl/J/
gUYdMomWUcAvkwxa/IuP9SbS2WQxdZot1YPSSM7T0v1iUfHeKa7Ahyf+oIbRi7AI
cDwntMqnOimIN58879ADe6kKCVBITFk9rLXWxq0fWqHGH79sIHh1A47tQ9E/hP0d
Cpzk4fR0kzp3Jb8mbe6yxWIgf5X7zoHs4MdtlCiQJUJDVjwkQ4hubhcaypEzKar8
o4+INk6IRcsjY+LYX8rIXhTcXXRVemz74TMbyyVgpHlGj5Sp4Wek0o3rNdk2Bui8
1uHJTC/5u4lw3FZJw00VhHI9YA2JptPzXbAKuVgcgzZLRVJDDrl+m50PVY+pK1Dh
M7b//SlQoM/1RC9T0s659J5Q383SxDY/EwM3UwWE+9mIX50hvw8x91/UvHycVxRA
kUj4V1mCC1EdOlO/HvB+kYsVEYlLp9vOTBGwhFRZVSxco7eNOJH9WArveKxrJP28
9ds61xMyjY8vIn07GlOQlMTWkRe7o8LcC5dsZTs++yc3AgMBAAEwDQYJKoZIhvcN
AQELBQADggIBAF4xf6bcz2plO5VR2xFf+cox2yWtCUfZvq1RwCWNL7OIMvueXK4A
CXVSqUG/sfwRq/+HyK7456jjOoETDzHNcv3S9+xopwILz9yr+V44VfMR6hLiHeE/
CRk3pZTn5IzUYyKnh+llp2kGhO41ZH0Iw72T0D+8QqGpnDryPMgoyg5Z39BIu/t+
kHXCHR1hm7rlgge8ho5s8XE8q2iUQ60ymXM0D5Ah1SKpCPoivNpsN9uEWkF8bEuh
hml7NoCVgl+0njBWL4jxxJK1WtEwdWyOrqXXDGGiF3ZPjlWUo/fy+Be4HVxx9Zu2
3emhCX9cyeVOkjuntW9CSNsK6Q3xyEa9YOuCRzlhCXw8+f4fMhjrEJ8c9mmJSE+4
RCaGS0zTzJ5NYxpGRgVmyWsdr9tZl2sfXWluwenQP1M4r9LfWQ3xgZGjmX0+XxFB
ssK7wOwQSHtvY92lx1YhxU93In25g+vpY2em2+z9e7TW/P9QccT5BhUs0+y1LzR3
rWdQpdHiMKm2IllCHmY2XLEtQBuggZrRSvfkOwb9pZmCeaKyogE0+hyyGBzwJaDT
DNTAKpwp7T2M+t+oc7BtbMdmtEozort6CdRr85eEP/PtEtW+USbsp7hD5C12ZnjX
/XfjR4nWsqjxwGsCJUDlXHR9AxtbU+F9HC3QYj3lj10HjCmO3PW/5FVf
-----END CERTIFICATE-----`

const TestRootKey string = `-----BEGIN PRIVATE KEY-----
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
Gg0vTVqwBlBsYFn5FmMjSAp/E5ab30k=
-----END PRIVATE KEY-----`

const TestIntermediateCert string = `-----BEGIN CERTIFICATE-----
MIID0TCCAbmgAwIBAgIBAjANBgkqhkiG9w0BAQUFADB1MRYwFAYDVQQDDA1GRE8g
VEVTVCBST09UMSIwIAYJKoZIhvcNAQkBFhNpbmZvQHdlYmF1dGhuLndvcmtzMRcw
FQYDVQQKDA5XZWJhdXRobiBXb3JrczELMAkGA1UEBhMCTloxETAPBgNVBAcMCFRh
dXJhbmdhMB4XDTIyMDEyMzE2MDIyOVoXDTQ5MDYxMDE2MDIyOVowfTEeMBwGA1UE
AwwVRkRPIFRFU1QgSU5URVJNRURJQVRFMSIwIAYJKoZIhvcNAQkBFhNpbmZvQHdl
YmF1dGhuLndvcmtzMRcwFQYDVQQKDA5XZWJhdXRobiBXb3JrczELMAkGA1UEBhMC
TloxETAPBgNVBAcMCFRhdXJhbmdhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
EHbg0OZ9vOAP0LpyAvBzokps4frssgppoqrZsyA8tQOtHSSEHE+F1j2Ja0MQTl3T
wCO3n4Dg1sYL1yWt5A+uMKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUPqcG
csIQK5h2fz7cyQW31/P5pwQwDQYJKoZIhvcNAQEFBQADggIBADqy21+uSI6692mW
oIb5wAHONSAo9ik68aI/DEsnbxtUo/k9fj9SUMKHCoktdf3NOrBdTNSJCDwUwYrT
sQSuC2r1WsW/qn/1GVoWEdNkDYitmbcuBT8w1JTmy/zvtvHMLIgjP/woJ27d7Dr/
NYjH1w8Sd+Zyq/ta2skWfQ+L7bZFkIu4pKbyASfmHkxUFOLxQGofvFQuwmOGKrNr
OHIelWhvWuKt+s14oqUO3DFCLFQrhxbeykwKLos/9Dj8QSYy7D6LMiTASKhMl4qS
6+TodSpvoPYlL+6tp+ASWrea8uOGpnOUY8slL77ew7kH295MH8CTHpXRMhYAkQwC
NoL8zOcsDFQP9kRS/pYd6L0UZMu91uppz7KKTOPXOP/qduH8wiHxYRk9Dhe1lu8y
PWVxzswDD5GQdoUxstWnatbZE7hTZDMxcPXEDVRL4J9dJzkkj2HYboxVUjIsEeTE
NIPgfcxikzirCNoSX3/Hn/0ZTxB9KMA8yQsBtvy0rqQKYa4YO0HjAaTJr0s4ukzW
kUKpib6rFaXUQtYZTrt9tQJlWahUV8t3Rzh2+fw6DYxbVzUYoHf9B14YexErLyEZ
AHcSqkdEtfFd5CrYD0ENefV7HyILNk+myCZeV1PPVAR4YGnBlIUtqvLo4shoqt4q
qyfH0feZCsS0U2NwyxuLNxzSKkRz
-----END CERTIFICATE-----`

const TestIntermediateKey string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOJHZr0XiREvz3yvtMRIcyHHzOVeNLbmbB7JEDq+fDx3oAoGCCqGSM49
AwEHoUQDQgAEEHbg0OZ9vOAP0LpyAvBzokps4frssgppoqrZsyA8tQOtHSSEHE+F
1j2Ja0MQTl3TwCO3n4Dg1sYL1yWt5A+uMA==
-----END EC PRIVATE KEY-----`

type WawDeviceCredBase struct {
	_                      struct{} `cbor:",toarray"`
	DCCertificateChain     []X509CertificateBytes
	DCPrivateKeyDer        []byte
	DCHmacAlg              HashType
	DCSgType               DeviceSgType
	DCCertificateChainHash HashOrHmac
	FdoGuid                FdoGuid
}

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

func NewWawDeviceCredBase(hmacAlgorithm HashType, sgType DeviceSgType) (*WawDeviceCredBase, error) {
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

	dcCertificateChainHash, _ := ComputeOVDevCertChainHash(dcCertificateChain, HmacToHashAlg[hmacAlgorithm])

	return &WawDeviceCredBase{
		DCCertificateChain:     dcCertificateChain,
		DCPrivateKeyDer:        marshaledPrivateKey,
		DCHmacAlg:              hmacAlgorithm,
		DCSgType:               sgType,
		DCCertificateChainHash: dcCertificateChainHash,
		FdoGuid:                newGuid,
	}, nil
}

func NewWawDeviceCredential(deviceCredBase WawDeviceCredBase) (*WawDeviceCredential, error) {
	// Generate HmacSecret
	var hmacSecret []byte = NewHmacKey(deviceCredBase.DCHmacAlg)

	dcSigInfo := SigInfo{
		SgType: deviceCredBase.DCSgType,
		Info:   []byte("virtual-device"),
	}

	return &WawDeviceCredential{
		DCProtVer:    ProtVer101,
		DCHmacSecret: hmacSecret,
		DCHmacAlg:    deviceCredBase.DCHmacAlg,
		DCHashAlg:    deviceCredBase.DCCertificateChainHash.Type,
		DCDeviceInfo: "I am a virtual FIDO Alliance device!",
		DCGuid:       deviceCredBase.FdoGuid,
		DCSigInfo:    dcSigInfo,
		DCRVInfo: []RendezvousInstrList{
			{
				// {
				// 	Key: RVDns,
				// 	Value: ,
				// },
			},
		},
		// DCPubKeyHash - come later via UpdateWithManufacturerCred

		DCPrivateKeyDer:        deviceCredBase.DCPrivateKeyDer,
		DCCertificateChain:     deviceCredBase.DCCertificateChain,
		DCCertificateChainHash: deviceCredBase.DCCertificateChainHash,
	}, nil
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

func RandomSgType() DeviceSgType {
	for {
		randLoc := NewRandomInt(0, len(SgTypeList)-1)

		if SgTypeList[randLoc] != StEPID10 && SgTypeList[randLoc] != StEPID11 {
			return SgTypeList[randLoc]
		}
	}
}
