package fdoshared

import (
	"testing"
)

func TestGenerateCoseSignature_ECDSACoefficients(t *testing.T) {
	for i := 0; i < 10000; i++ {
		privKey, pubKey, err := GeneratePKIXECKeypair(StSECP256R1)
		if err != nil {
			t.Fatalf("ES256: failed to generate private key: %v", err)
		}

		coseSig, err := GenerateCoseSignature([]byte("test"), ProtectedHeader{}, UnprotectedHeader{}, privKey, StSECP256R1)
		if err != nil {
			t.Fatalf("ES256: failed to generate COSE signature: %v", err)
		}

		if len(coseSig.Signature) != 64 {
			t.Fatalf("ES256: Invalid signature length run(%d) length(%d)", i, len(coseSig.Signature))
		}

		err = VerifyCoseSignature(*coseSig, *pubKey)
		if err != nil {
			t.Fatalf("failed to verify COSE signature: %v", err)
		}
	}

	for i := 0; i < 10000; i++ {
		privKey, pubKey, err := GeneratePKIXECKeypair(StSECP384R1)
		if err != nil {
			t.Fatalf("ES384: failed to generate private key: %v", err)
		}

		coseSig, err := GenerateCoseSignature([]byte("test"), ProtectedHeader{}, UnprotectedHeader{}, privKey, StSECP384R1)
		if err != nil {
			t.Fatalf("ES384: failed to generate COSE signature: %v", err)
		}

		if len(coseSig.Signature) != 96 {
			t.Fatalf("ES384: Invalid signature length run(%d) length(%d)", i, len(coseSig.Signature))
		}

		err = VerifyCoseSignature(*coseSig, *pubKey)
		if err != nil {
			t.Fatalf("failed to verify COSE signature: %v", err)
		}
	}
}

func TestGenerateCoseSignature(t *testing.T) {
	payload := []byte("test payload")
	protected := ProtectedHeader{Alg: GetIntRef(int(StSECP256R1))}
	unprotected := UnprotectedHeader{}

	privKey, pubKey, err := GeneratePKIXECKeypair(StSECP256R1)
	if err != nil {
		t.Fatalf("ES256: failed to generate private key: %v", err)
	}

	sgType := StSECP256R1

	signature, err := GenerateCoseSignature(payload, protected, unprotected, privKey, sgType)
	if err != nil {
		t.Fatalf("failed to generate COSE signature: %v", err)
	}

	err = VerifyCoseSignature(*signature, *pubKey)
	if err != nil {
		t.Fatalf("failed to verify COSE signature: %v", err)
	}
}
