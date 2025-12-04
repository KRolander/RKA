// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package ec_kem

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/KRolander/RKA/hmqv"

	"errors"
	"hash"
	"math/big"

	"github.com/cloudflare/circl/dh/x25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"filippo.io/edwards25519"
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

// EC-DEKEM with x25519 curve - which is a safe curve, other arithmetics of "crypto/elliptic"
// cannot be computed safely - DEPRICATED !
// q is the recipient private key
// C is the encapsulated key
// returns K the initially encapsulated secret key used for data exchange
// K = q * C -> K = q * (r*G) -> K = r*(q*G) -> K = r * Q
func EC_dekem_x25519(q []byte, C []byte) ([]byte, error) {

	SK, err := curve25519.X25519(q, C)
	if err != nil {
		return nil, fmt.Errorf("error in ScalarMult")
	}

	return SK, nil

}

// EC-KEM with x25519 curve - which is a safe curve, other arithmetics of "crypto/elliptic"
// cannot be computed safely - DEPRICATED !
// In the original ecies-kem scheme r is generated in the scheme (randomly picked up)
// In this version the r is an argument (r must be random)
// Q is the recipient's public key
// C is the encapsulated key -> (r), the recipiet (Q, q) can compute K = q * C -> q * (r * G) -> K = r*Q
// K used as secret key for data encryption

func EC_kem_x25519(r []byte, Q []byte) ([]byte, []byte, error) {

	C, err := curve25519.X25519(r, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error in ScalarBaseMult")
	}

	SK, err := curve25519.X25519(r, Q)
	if err != nil {
		return nil, nil, fmt.Errorf("error in ScalarMult")
	}

	return C, SK, nil

}

func GenKeyPair_curve25519() (x25519.Key, x25519.Key) {
	var pub x25519.Key
	var priv x25519.Key
	_, _ = io.ReadFull(rand.Reader, priv[:])
	x25519.KeyGen(&pub, &priv)

	return priv, pub
}

func GenerateKeyPair_edwards25519() ([]byte, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return priv.Seed(), priv.Public().(ed25519.PublicKey), nil
	// var privKeyBytes [32]byte
	// _, _ = io.ReadFull(rand.Reader, privKeyBytes[:])

	// privateKey, err := new(edwards25519.Scalar).SetBytesWithClamping(privKeyBytes[:])
	// if err != nil {
	// 	return nil, nil, err
	// }

	// // pub = privateKey * B, where B is the base point
	// pub := new(edwards25519.Point).ScalarBaseMult(privateKey)

	// // Canonical 32-byte encoding of v
	// pubKey := pub.Bytes()

	// return privateKey.Bytes(), pubKey, err

}

// EC-KEM with x25519 curve - which is a safe curve, other arithmetics of "crypto/elliptic"
// cannot be computed safely - DEPRICATED !
// In the original ecies-kem scheme r is generated in the scheme (randomly picked up)
// In this version the r is an argument (r must be random)
// Q is the recipient's public key
// C is the encapsulated key -> (r), the recipiet (Q, q) can compute K = q * C -> q * (r * G) -> K = r*Q
// K used as secret key for data encryption
func EC_KEM_edwards25519(r []byte, Q []byte) ([]byte, []byte, error) {

	r_scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(r)
	if err != nil {
		return nil, nil, fmt.Errorf("error in SetCanonicalBytes - %v", err)
	}

	C_point := new(edwards25519.Point).ScalarBaseMult(r_scalar)

	C := C_point.Bytes()

	Q_point, err := new(edwards25519.Point).SetBytes(Q)
	if err != nil {
		return nil, nil, fmt.Errorf("error in SetBytes - %v", err)
	}

	SK_point := new(edwards25519.Point).ScalarMult(r_scalar, Q_point)

	SK := SK_point.Bytes()

	return C, SK, nil
}

// EC-DEKEM with x25519 curve - which is a safe curve, other arithmetics of "crypto/elliptic"
// cannot be computed safely - DEPRICATED !
// q is the recipient private key
// C is the encapsulated key
// returns K the initially encapsulated secret key used for data exchange
// K = q * C -> K = q * (r*G) -> K = r*(q*G) -> K = r * Q
func EC_DEKEM_edwards25519(q []byte, C []byte) ([]byte, error) {

	// q_scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(q)
	q_scalar, err := hmqv.Construct_RFC8032_Scalar(q)
	if err != nil {
		return nil, fmt.Errorf("error in SetCanonicalBytes - %v", err)
	}

	C_point, err := new(edwards25519.Point).SetBytes(C)
	if err != nil {
		return nil, fmt.Errorf("error in SetBytes - %v", err)
	}

	SK_point := new(edwards25519.Point).ScalarMult(q_scalar, C_point)

	SK := SK_point.Bytes()

	return SK, nil

}
