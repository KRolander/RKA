package ec_kem

import (
	"crypto/elliptic"

	"errors"
	"hash"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// derived from kyber/encrypt/ecies.go
// key_m : key material used to derive hkdf generated keys

func DeriveCommitKey(hash func() hash.Hash, key_m []byte, len int) ([]byte, error) {

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

func EC_kem(c elliptic.Curve, r []byte, Q []byte) ([]byte, []byte) {

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

func EC_dekem(c elliptic.Curve, q []byte, C []byte) []byte {

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
