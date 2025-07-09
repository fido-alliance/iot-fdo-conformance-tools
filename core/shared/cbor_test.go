package fdoshared

import (
	"encoding/hex"
	"testing"
)

func TestCBOR_CUSTOM_TAGS_Unmarshal(t *testing.T) {
	// CoseSig
	coseSig := CoseSignature{}
	bts, err := CborCust.Marshal(coseSig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hex.EncodeToString(bts) != "d284f6a0f6f6" {
		t.Fatalf("expected cosesign to encode to \"d284f6a0f6f6\". Got %v", hex.EncodeToString(bts))
	}

	// CoseMac
	coseMac := COSEMacStructure{}
	bts, err = CborCust.Marshal(coseMac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hex.EncodeToString(bts) != "d18460a0f6f6" {
		t.Fatalf("expected cosemac to encode to \"d18460a0f6f6\". Got %v", hex.EncodeToString(bts))
	}

	// ETMInnerBlock / EMBlock
	etmInnerBlock := EMB_ETMInnerBlock{}
	bts, err = CborCust.Marshal(etmInnerBlock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hex.EncodeToString(bts) != "d083f6a0f6" {
		t.Fatalf("expected etminnerblock to encode to \"d083f6a0f6\". Got %v", hex.EncodeToString(bts))
	}
}
