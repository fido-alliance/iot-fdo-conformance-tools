package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

	return xAKeyExchange, priva
}

// func finishKeyExchange(keyExchange fdoshared.XAKeyExchange, keyExchange2 fdoshared.XAKeyExchange, privKey ecdsa.PrivateKey, isDO bool) []byte {
func finishKeyExchange(keyExchange fdoshared.XAKeyExchange, keyExchange2 fdoshared.XAKeyExchange, privKey interface{}, isDO bool) []byte {

	x, y, r, _ := extractBytesFromKeyExchange(keyExchange) // extract x,y,r from other party's keyExchange struct
	// err handling
	_, _, r2, _ := extractBytesFromKeyExchange(keyExchange2) // extract r from own keyExhange. This can be optimised
	// err handling

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
func extractBytesFromKeyExchange(keyExchange fdoshared.XAKeyExchange) ([]byte, []byte, []byte, error) {

	xLen := int(binary.BigEndian.Uint16(keyExchange[0:2]))
	yLen := int(binary.BigEndian.Uint16(keyExchange[xLen+2 : xLen+4]))
	rLen := int(binary.BigEndian.Uint16(keyExchange[xLen+2+yLen+2 : xLen+2+yLen+2+2]))

	xA_x := (keyExchange[2 : xLen+2])
	xA_y := (keyExchange[xLen+4 : xLen+4+yLen])
	r := (keyExchange[xLen+4+yLen+2 : xLen+4+yLen+2+rLen])
	if xLen+4+yLen+2+rLen != len(keyExchange) {
		return nil, nil, nil, errors.New("Detected bytes != actual length")
	}

	return xA_x, xA_y, r, nil
}

func convertCoefficientsToBigInt(x []byte, y []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
}

/*
#1

keyExchange=
[0 32 113 127 113 68 86 76 241 0 93 196 206 247 74 94 22 186 240 124 99 120 195 58 33 14 215 132 203 181 242 97 107 130
0 32 43 37 71 218 7 175 120 191 190 17 21 193 108 226 94 101 195 81 244 161 175 162 33 125 81 104 180 172 166 1 238 237
0 16 123 31 134 216 211 52 20 117 196 42 107 113 242 40 31 193]
=>
x=[113 127 113 68 86 76 241 0 93 196 206 247 74 94 22 186 240 124 99 120 195 58 33 14 215 132 203 181 242 97 107 130]
y=[43 37 71 218 7 175 120 191 190 17 21 193 108 226 94 101 195 81 244 161 175 162 33 125 81 104 180 172 166 1 238 237]
r=[123 31 134 216 211 52 20 117 196 42 107 113 242 40 31 193]

*/
