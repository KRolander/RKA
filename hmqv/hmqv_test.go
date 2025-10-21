package hmqv

import (
	"ardka/ec_kem"
	"crypto/sha256"
	"fmt"
	"testing"
)

//func TestAgree(t *testing.T) {
//	var tests = []struct {
//		a, b int
//		want int
//	}{
//		{0, 1, 0},
//		{1, 0, 0},
//		{2, -2, -2},
//		{0, -1, -1},
//		{-1, 0, -1},
//	}
//	for _, tt := range tests {
//
//		testname := fmt.Sprintf("%d,%d", tt.a, tt.b)
//		t.Run(testname, func(t *testing.T) {
//			ans := IntMin(tt.a, tt.b)
//			if ans != tt.want {
//				t.Errorf("got %d, want %d", ans, tt.want)
//			}
//		})
//	}
//
//}

func BenchmarkHMQV(b *testing.B) {
	// Setup
	sprivA_Int, spubA_x_Int, spubA_y_Int := GenerateKeys()
	staticKeysAlice := StaticKeys{sprivA_Int, spubA_x_Int, spubA_y_Int}
	sprivB_Int, spubB_x_Int, spubB_y_Int := GenerateKeys()
	staticKeysBob := StaticKeys{sprivB_Int, spubB_x_Int, spubB_y_Int}
	h := sha256.New

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Epheremal keys
		eprivA_Int, epubA_x_Int, epubA_y_Int := GenerateKeys()
		ephemeralKeysAlice := EphemeralKeys{eprivA_Int, epubA_x_Int, epubA_y_Int}
		eprivB_Int, epubB_x_Int, epubB_y_Int := GenerateKeys()
		ephemeralKeysBob := EphemeralKeys{eprivB_Int, epubB_x_Int, epubB_y_Int}
		km := Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
		_, err := ec_kem.DeriveCommitKey(h, km, 64)
		if err != nil {
			b.Fail()
		}
	}
}

func TestHMQV_edwards25519(t *testing.T) {
	sprivA, spubA, err := GenerateKeyPair_edwards25519()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysAlice := StaticKeys_edwards25519{sprivA, spubA}

	sprivB, spubB, err := GenerateKeyPair_edwards25519()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysBob := StaticKeys_edwards25519{sprivB, spubB}

	////////////////////////////////////////////////////

	eprivA, epubA, err := GenerateKeyPair_edwards25519()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	ephemeralKeysAlice := EphemeralKeys_edwards25519{eprivA, epubA}

	eprivB, epubB, err := GenerateKeyPair_edwards25519()
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
