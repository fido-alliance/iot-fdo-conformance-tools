package main

// https://replit.com/@billbuchanan/ecdh3#main.go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"fmt"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
)

func extractComponentsFromKeyExchange(keyExchange fdoshared.XAKeyExchange) bool {
	// mySlice := keyExchange{}
	// log.Println(keyExchange[:1])
	// data := binary.BigEndian.Uint64(mySlice)
	return false
}

/**
export const extractComponentsFromKeyExchange = (keyExchange: Buffer) => {
  let i = 0;

  const xLen = keyExchange.slice(0, 2).readInt16LE();
  const x = keyExchange.slice(2, 2 + xLen);
  i = 2 + xLen;

  const yLen = keyExchange.slice(i, i + 2).readInt16LE();
  const y = keyExchange.slice(i + 2, i + 2 + xLen);
  i = i + 2 + yLen;

  const randomLen = keyExchange.slice(i, i + 2).readInt16LE();
  const theirRandom = keyExchange.slice(i + 2, i + 2 + randomLen);

  return { x, y, theirRandom };
};
**/

// TODO : Lengths are being stored as numbers in the byte array... eg 32 should be 20
func beginECDHKeyExchange(curve fdoshared.KexSuiteName) (fdoshared.XAKeyExchange, *ecdsa.PrivateKey) {

	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	puba := priva.PublicKey

	fmt.Printf("\nPrivate key (Alice) %x", priva.D)

	fmt.Printf("\nPublic key (Alice) (%x,%x)", puba.X, puba.Y)

	var randomBytesLength uint8
	if curve == fdoshared.ECDH256 {
		randomBytesLength = 16
	} else {
		randomBytesLength = 48
	}

	var lenX = big.NewInt(int64(len(puba.X.Bytes()))).Bytes()
	var lenY = big.NewInt(int64(len(puba.Y.Bytes()))).Bytes()

	randomBytes := make([]byte, randomBytesLength)
	rand.Read(randomBytes)
	var lenRandom = big.NewInt(int64(randomBytesLength)).Bytes()

	var xAKeyExchange fdoshared.XAKeyExchange = append(lenX, puba.X.Bytes()...)
	xAKeyExchange = append(xAKeyExchange, lenY...)
	xAKeyExchange = append(xAKeyExchange, puba.Y.Bytes()...)
	xAKeyExchange = append(xAKeyExchange, lenRandom...)
	xAKeyExchange = append(xAKeyExchange, randomBytes...)

	return xAKeyExchange, priva
}
