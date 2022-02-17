package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"log"
	"math/big"

	"github.com/WebauthnWorks/fdo-do/fdoshared"
)

func beginECDHKeyExchange(curve fdoshared.KexSuiteName) (fdoshared.XAKeyExchange, *ecdsa.PrivateKey) {

	// generate keys
	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	puba := priva.PublicKey

	var randomBytesLength uint8

	if curve == fdoshared.ECDH256 {
		randomBytesLength = 16
	} else {
		randomBytesLength = 48
	}

	// Convert public key x,y to bytes

	xLen := make([]byte, 2)
	binary.BigEndian.PutUint16(xLen, uint16(len(puba.X.Bytes())))
	yLen := make([]byte, 2)
	binary.BigEndian.PutUint16(yLen, uint16(len(puba.Y.Bytes())))

	// var lenX = big.NewInt(int64(len(puba.X.Bytes()))).Bytes()
	// var lenY = big.NewInt(int64(len(puba.Y.Bytes()))).Bytes()

	// Create device/owner random
	lenRandom := make([]byte, 2)
	randomBytes := make([]byte, randomBytesLength)
	binary.BigEndian.PutUint16(lenRandom, uint16(len(randomBytes)))
	rand.Read(randomBytes)

	// Assemble into keyExchange
	var xAKeyExchange fdoshared.XAKeyExchange = append(xLen, puba.X.Bytes()...)
	xAKeyExchange = append(xAKeyExchange, yLen...)
	xAKeyExchange = append(xAKeyExchange, puba.Y.Bytes()...)
	xAKeyExchange = append(xAKeyExchange, lenRandom...)
	xAKeyExchange = append(xAKeyExchange, randomBytes...)
	log.Println(xAKeyExchange)

	return xAKeyExchange, priva
}

// func finishKeyExchange(keyExchange fdoshared.XAKeyExchange, keyExchange2 fdoshared.XAKeyExchange, privKey ecdsa.PrivateKey, isDO bool) []byte {
func finishKeyExchange(keyExchange fdoshared.XAKeyExchange, keyExchange2 fdoshared.XAKeyExchange, privKey interface{}, isDO bool) []byte {

	x, y, r := extractBytesFromKeyExchange(keyExchange) // extract x,y,r from other party's keyExchange struct

	_, _, r2 := extractBytesFromKeyExchange(keyExchange2) // extract r from own keyExhange. This can be optimised

	bigX, bigY := convertCoefficientsToBigInt(x, y) // coverts other party's bytes into bigInt for scalar multipl.

	switch privKey := privKey.(type) {
	case *ecdsa.PrivateKey:

		pubKey := privKey.PublicKey                                      // regenerates public from personal private key
		shx, _ := pubKey.Curve.ScalarMult(bigX, bigY, privKey.D.Bytes()) // calculates sharedSecret

		// creates sharedSecret by appending owner/device randoms in appropriate order
		shSe := shx.Bytes()
		if isDO {
			shSe = append(shSe, r2...)
			shSe = append(shSe, r...)
		} else {
			shSe = append(shSe, r...)
			shSe = append(shSe, r2...)
		}

		return shSe

	}

	return nil
}

// See #1 at end of file for example
func extractBytesFromKeyExchange(keyExchange fdoshared.XAKeyExchange) ([]byte, []byte, []byte) {
	xLen := int(keyExchange[0])

	xA_x := (keyExchange[1 : xLen+1])

	yLen := int(keyExchange[xLen+1])

	xA_y := (keyExchange[xLen+2 : xLen+2+yLen])

	rLen := int(keyExchange[xLen+2+yLen])
	r := (keyExchange[xLen+2+yLen+1 : xLen+2+yLen+1+rLen])

	return xA_x, xA_y, r
}

func convertCoefficientsToBigInt(x []byte, y []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
}

/*
#1

keyExchange=[32 113 127 113 68 86 76 241 0 93 196 206 247 74 94 22 186 240 124 99 120 195 58 33 14 215 132 203 181 242 97 107 130 32 43 37 71 218 7 175 120 191 190 17 21 193 108 226 94 101 195 81 244 161 175 162 33 125 81 104 180 172 166 1 238 237 16 123 31 134 216 211 52 20 117 196 42 107 113 242 40
31 193] =>
x=[113 127 113 68 86 76 241 0 93 196 206 247 74 94 22 186 240 124 99 120 195 58 33 14 215 132 203 181 242 97 107 130]
y=[43 37 71 218 7 175 120 191 190 17 21 193 108 226 94 101 195 81 244 161 175 162 33 125 81 104 180 172 166 1 238 237]
r=[123 31 134 216 211 52 20 117 196 42 107 113 242 40 31 193]

*/

// https://replit.com/@billbuchanan/ecdh3#main.go for reference

// Correct payload
// 8441a0a2190100830000f639010250f903e79c696e27c964b45d5681efa39b5881a30a5007c8010ad7a2222817c7cb359f282c090b51018d62ddb18b404cf58cf5f22cef5c457639010058562000dfd7f60fd078854e0d5f9bc7b421da2c39f311ddc01ee174fe482e32e9fee9b6200035c01ae73cac5e5d6c4e6e066e5dcb21e993b5999bc727c8a7b0c6f3391b73811000b76088069d6c93eed688fe179166691558409e50882b63f1549a1f29cbb634248bcd08948654bc73a73d347f468358a909ef45c2c74318f342ffecc4fa3f36020cf8fb5d6e2cccb6f1f97ea6d08669106e82

// Temp
// 8441a0a2190100830000f639010250f903e79c696e27c964b45d5681efa39b5881a30a5007c8010ad7a2222817c7cb359f282c090b51018d62ddb18b404cf58cf5f22cef5c4576390100585620dfd7f60fd078854e0d5f9bc7b421da2c39f311ddc01ee174fe482e32e9fee9b62035c01ae73cac5e5d6c4e6e066e5dcb21e993b5999bc727c8a7b0c6f3391b738110b76088069d6c93eed688fe179166691558409e50882b63f1549a1f29cbb634248bcd08948654bc73a73d347f468358a909ef45c2c74318f342ffecc4fa3f36020cf8fb5d6e2cccb6f1f97ea6d08669106e82
