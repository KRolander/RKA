package hmqv

import (
	"fmt"
	"testing"
)

func TestHMQV_edwards25519(t *testing.T) {
	sprivA, spubA, err := GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysAlice := StaticKeys_edwards25519{sprivA, spubA}

	sprivB, spubB, err := GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysBob := StaticKeys_edwards25519{sprivB, spubB}

	////////////////////////////////////////////////////

	eprivA, epubA, err := GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	ephemeralKeysAlice := EphemeralKeys_edwards25519{eprivA, epubA}

	eprivB, epubB, err := GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	ephemeralKeysBob := EphemeralKeys_edwards25519{eprivB, epubB}

	km_a, err := Agree_edwards25519(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Alice - Km: %x\n", km_a)

	km_b, err := Agree_edwards25519(&staticKeysBob, &ephemeralKeysBob, &staticKeysAlice, &ephemeralKeysAlice, false)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Bob - km_b: %x\n", km_b)
}
