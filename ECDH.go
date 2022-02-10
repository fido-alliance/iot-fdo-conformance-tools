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

// TODO : Lengths are being stored as numbers in the byte array... eg 32 should be 20

func beginECDHKeyExchange(curve fdoshared.KexSuiteName) (fdoshared.XAKeyExchange, error) {

	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privb, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	puba := priva.PublicKey
	pubb := privb.PublicKey

	fmt.Printf("\nPrivate key (Alice) %x", priva.D)
	fmt.Printf("\nPrivate key (Bob) %x\n", privb.D)

	fmt.Printf("\nPublic key (Alice) (%x,%x)", puba.X, puba.Y)
	fmt.Printf("\nPublic key (Bob) (%x %x)\n", pubb.X, pubb.Y)

	var randomBytesLength uint8
	if curve == fdoshared.ECDH256 {
		randomBytesLength = 16
	} else {
		randomBytesLength = 48
	}
	fmt.Printf("\nCurve: %x", string(curve[:]))
	fmt.Printf("\nCurve: %x", randomBytesLength)

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

	log.Println(big.NewInt(int64(len(puba.X.Bytes()))))
	log.Println(xAKeyExchange)

	// a, _ := puba.Curve.ScalarMult(puba.X, puba.Y, privb.D.Bytes())
	// b, _ := pubb.Curve.ScalarMult(pubb.X, pubb.Y, priva.D.Bytes())

	// shared1 := sha256.Sum256(a.Bytes())
	// shared2 := sha256.Sum256(b.Bytes())

	return xAKeyExchange, nil
}
