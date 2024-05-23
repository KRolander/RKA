// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package ec_sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	// myECDH "github.com/aead/ecdh"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func KeyGen() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return StructurizeECDSAKeys(privateKey.D.Bytes(), privateKey.X, privateKey.Y)
}

// Create ECDSA key structure
func StructurizeECDSAKeys(privkey []byte, pubkey_x *big.Int, pubkey_y *big.Int) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int).SetBytes(privkey)
	privKey.X = pubkey_x
	privKey.Y = pubkey_y
	privKey.PublicKey.Curve = elliptic.P256()

	pubKey := privKey.PublicKey

	return privKey, &pubKey
}

// ECDSA sign algorithm using P-256 curve by default
func Sign(privkey *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int) {
	r, s, _ := ecdsa.Sign(rand.Reader, privkey, digest)

	return r, s
}

// Verifies the validity of the signature
func Verify(pubkey *ecdsa.PublicKey, digest []byte, r *big.Int, s *big.Int) bool {
	return ecdsa.Verify(pubkey, digest, r, s)

}

// Represents the r and s components of the signature as a byte array
func Compress_Signature(r *big.Int, s *big.Int) []byte {

	sigma := make([]byte, 0)
	sigma = append(sigma, r.Bytes()...)
	sigma = append(sigma, s.Bytes()...)

	return sigma
}

// Convert Byte array representation of [r,s] into *big.Int r, *big.Int s
func Uncompress_Signature(sigma []byte) (r *big.Int, s *big.Int) {

	sigmaR := new(big.Int).SetBytes(sigma[:32])
	sigmaS := new(big.Int).SetBytes(sigma[32:])

	return sigmaR, sigmaS
}
