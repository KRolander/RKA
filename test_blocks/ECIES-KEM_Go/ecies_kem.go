// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"os"

	"encoding/hex"
	"errors"
	"hash"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type StaticKeys struct {
	privateKey  *big.Int
	publicKey_x *big.Int
	publicKey_y *big.Int
}

type EphemeralKeys struct {
	privateKey  *big.Int
	publicKey_x *big.Int
	publicKey_y *big.Int
}

func main() {
	h := sha256.New
	c := elliptic.P256()
	// c := elliptic.P256()

	// Private/Public Key of the recipient
	privA, _ := hex.DecodeString("7373160a11bfaa963a35e4ca0bad8231c281c1da1153e395e9bafd38adad67bb")
	privA_Int := new(big.Int)
	privA_Int.SetBytes(privA)
	pubA_x_Int, pubA_y_Int := c.ScalarBaseMult(privA_Int.Bytes())

	Q_A := make([]byte, 0)
	Q_A = append(Q_A, pubA_x_Int.Bytes()...)
	Q_A = append(Q_A, pubA_y_Int.Bytes()...)

	fmt.Printf("Recipient Pubkey %x %x\n", pubA_x_Int, pubA_y_Int)

	// Key material
	K_m, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")

	r, err := deriveCommitKey(h, K_m, 64)

	r1 := r[:32]
	r2 := r[32:]

	if err != nil {
		fmt.Println("Error in deriveCommitKey")
		os.Exit(1)
	}

	fmt.Printf("k_r : %x\n", r1)
	fmt.Printf("k_q : %x\n", r2)

	Cr, Kr := ec_kem(c, r1, Q_A)

	fmt.Printf("Cr : %x\nKr : %x\n", Cr, Kr)

	Kr_dec := ec_dekem(c, privA, Cr)

	fmt.Printf("Kr after ec_dekem: %x\n", Kr_dec)

}

// derived from kyber/encrypt/ecies.go
// key_m : key material used to derive hkdf generated keys

func deriveCommitKey(hash func() hash.Hash, key_m []byte, len int) ([]byte, error) {

	hkdf := hkdf.New(hash, key_m, nil, nil)
	key := make([]byte, len)

	n, err := hkdf.Read(key)
	if err != nil {
		return nil, err
	}
	if n < len {
		return nil, errors.New("ecies: hkdf-derived key too short")
	}
	return key, nil
}

// In the original ecies-kem scheme r is generated in the scheme (randomly picked up)
// In this version the r is an argument (r must be random)
// Q is the recipient's public key
// C is the encapsulated key -> (r), the recipiet (Q, q) can compute K = q * C -> q * (r * G) -> K = r*Q
// K used as secret key for data encryption

func ec_kem(c elliptic.Curve, r []byte, Q []byte) ([]byte, []byte) {

	r_Int := new(big.Int)
	r_Int.SetBytes(r)

	Qx_Int := new(big.Int)
	Qx_Int.SetBytes(Q[:32])

	Qy_Int := new(big.Int)
	Qy_Int.SetBytes(Q[32:]) // TODO remove 32

	Rx, Ry := c.ScalarBaseMult(r)

	Sx, Sy := c.ScalarMult(Qx_Int, Qy_Int, r)

	K := make([]byte, 0)
	K = append(K, Sx.Bytes()...)
	K = append(K, Sy.Bytes()...)

	C := make([]byte, 0)
	C = append(C, Rx.Bytes()...)
	C = append(C, Ry.Bytes()...)

	return C, K

}

// q is the recipient private key
// C is the encapsulated key
// returns K the initially encapsulated secret key used for data exchange
// K = q * C -> K = q * (r*G) -> K = r*(q*G) -> K = r * Q

func ec_dekem(c elliptic.Curve, q []byte, C []byte) []byte {

	Cx_Int := new(big.Int)
	Cx_Int.SetBytes(C[:32])

	Cy_Int := new(big.Int)
	Cy_Int.SetBytes(C[32:])

	Kx, Ky := c.ScalarMult(Cx_Int, Cy_Int, q)

	K := make([]byte, 0)
	K = append(K, Kx.Bytes()...)
	K = append(K, Ky.Bytes()...)

	return K
}
