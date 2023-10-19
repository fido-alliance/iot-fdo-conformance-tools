package fdoshared

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func test_generateSessionKeyInfo() SessionKeyInfo {
	return SessionKeyInfo{
		ShSe:        []byte("test ShSe"),
		ContextRand: []byte("test ContextRand"),
	}
}

func TestEncryptEMB(t *testing.T) {
	payload := []byte("test payload")
	sessionKeyInfo := test_generateSessionKeyInfo()

	cipherSuite := CIPHER_A128GCM

	encrypted, err := encryptEMB(payload, sessionKeyInfo, cipherSuite)
	if err != nil {
		t.Errorf("Error encrypting EMB: %v", err)
	}

	decrypted, err := decryptEMB(encrypted, sessionKeyInfo, cipherSuite)
	if err != nil {
		t.Errorf("Error decrypting EMB: %v", err)
	}

	if !bytes.Equal(payload, decrypted) {
		t.Errorf("Decrypted payload does not match original payload %s %s", hex.EncodeToString(payload), hex.EncodeToString(decrypted))
	}
}
