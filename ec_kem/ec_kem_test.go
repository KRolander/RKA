package ec_kem

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
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
