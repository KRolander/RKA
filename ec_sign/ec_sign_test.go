package ec_sign

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/KRolander/RKA/hmqv"
)

// Test compatibility with crypto/edwards25519
func TestKeyGen_edwards25519(t *testing.T) {

	sprivA, _, err := hmqv.GenerateKeyPair_edwards25519()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	priv_ed := ed25519.NewKeyFromSeed(sprivA)
	fmt.Printf("Key : %x\n", priv_ed)

}

func TestSign_Verfy_edwards25519(t *testing.T) {
	seed, pub, err := hmqv.GenerateKeyPair_edwards25519_()
	// pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Error in GenerateKeyPair_edwards25519_()!")
	}

	message := []byte("Hello World")

	priv := make([]byte, 0)
	priv = append(priv, seed...)
	priv = append(priv, pub...)

	signature := Sign_edwards25519(priv, message)

	if !ed25519.Verify(pub, message, signature) {
		t.Errorf("The signature is not valid !")
	} else {
		fmt.Printf("The signature is valid !\n")
	}

}
