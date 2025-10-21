package ec_kem

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
)

// Test of KEM and DEKEM with x25519 curve - which is a safe curve, other arithmetics of "crypto/elliptic"
// cannot be computed safely - DEPRICATED !
func TestEC_KEM_DEKEM(t *testing.T) {

	curve := ecdh.X25519()

	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey()

	// priv, pub := GenKeyPair_curve25519()

	fmt.Printf("Priv: %x\n", priv.Bytes())
	fmt.Printf("Pub:  %x\n", pub.Bytes())

	r, _ := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")

	C, SK, err := EC_kem_x25519(r, pub.Bytes())
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("C: %x\n", C)
	fmt.Printf("SK: %x\n", SK)

	_SK, err := EC_dekem_x25519(priv.Bytes(), C)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("_SK: %x\n", _SK)
}

func TestEC_KEM_DEKEM_ED25519(t *testing.T) {
	priv, pub, err := GenerateKeyPair_edwards25519()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	fmt.Printf("Private key: %x\n", priv)
	fmt.Printf("Public key: %x\n", pub)

	r_Bytes, _ := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")

	r_Scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(r_Bytes)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	r := r_Scalar.Bytes()

	C, SK, err := EC_KEM_edwards25519(r, pub)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	fmt.Printf("C: %x\n", C)
	fmt.Printf("SK: %x\n", SK)

	_SK, err := EC_DEKEM_edwards25519(priv, C)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	} else {
		fmt.Printf("_SK: %x\n", _SK)
	}

}
