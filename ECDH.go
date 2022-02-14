package main

// https://replit.com/@billbuchanan/ecdh3#main.go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"math/big"

	"fmt"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
)

func convertCoefficientsToBigInt(keyExchange fdoshared.XAKeyExchange) (*big.Int, *big.Int, []byte) {
	xLen := int(keyExchange[0])
	xA_x := (keyExchange[1 : xLen+1])

	yLen := int(keyExchange[xLen+1])
	xA_y := (keyExchange[xLen+2 : xLen+2+yLen])
	xA_x_Big := new(big.Int)
	xA_y_Big := new(big.Int)
	xA_x_Big.SetBytes(xA_x)
	xA_y_Big.SetBytes(xA_y)

	rLen := int(keyExchange[xLen+2+yLen])
	r := (keyExchange[xLen+2+yLen+1 : xLen+2+yLen+1+rLen])

	return xA_x_Big, xA_y_Big, r
}

// Completes Key Exchange from DO side using DI pub key
func completeKeyExchange(priva ecdsa.PrivateKey, pubDI ecdsa.PublicKey) {
	shx, _ := pubDI.Curve.ScalarMult(pubDI.X, pubDI.Y, priva.D.Bytes())
	// shx.append deviceRandom
	log.Println(shx)
}

func extractComponentsFromKeyExchange(keyExchange fdoshared.XAKeyExchange) ecdsa.PublicKey {
	log.Println(keyExchange)

	do_x, do_y, _ := convertCoefficientsToBigInt(keyExchange)

	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	puba := priva.PublicKey

	shx, _ := puba.Curve.ScalarMult(do_x, do_y, priva.D.Bytes())
	// shx.append doRandom

	log.Println(shx)

	return puba // return xBKeyExchange
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
