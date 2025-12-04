package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/KRolander/RKA/ec_kem"
	"github.com/KRolander/RKA/ec_sign"
	"github.com/KRolander/RKA/hmqv"

	"filippo.io/edwards25519"
)

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = hmqv.GenerateKeys()
		_, _ = ec_sign.KeyGen()
	}
}

func BenchmarkHMQV(b *testing.B) {
	// Setup
	sprivA_Int, spubA_x_Int, spubA_y_Int := hmqv.GenerateKeys()
	staticKeysAlice := hmqv.StaticKeys{sprivA_Int, spubA_x_Int, spubA_y_Int}
	sprivB_Int, spubB_x_Int, spubB_y_Int := hmqv.GenerateKeys()
	staticKeysBob := hmqv.StaticKeys{sprivB_Int, spubB_x_Int, spubB_y_Int}
	h := sha256.New

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Epheremal keys
		eprivA_Int, epubA_x_Int, epubA_y_Int := hmqv.GenerateKeys()
		ephemeralKeysAlice := hmqv.EphemeralKeys{eprivA_Int, epubA_x_Int, epubA_y_Int}
		eprivB_Int, epubB_x_Int, epubB_y_Int := hmqv.GenerateKeys()
		ephemeralKeysBob := hmqv.EphemeralKeys{eprivB_Int, epubB_x_Int, epubB_y_Int}
		km := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
		_, err := ec_kem.DeriveCommitKey(h, km, 64)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkSKEM(b *testing.B) {
	c := elliptic.P256()

	// Generate Static Pubkey of Board Member (BM)
	privBM, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")
	privBM_Int := new(big.Int)
	privBM_Int.SetBytes(privBM)

	pk_BM_x_Int, pk_BM_y_Int := c.ScalarBaseMult(privBM_Int.Bytes())

	pk_BM := make([]byte, 0)
	pk_BM = append(pk_BM, pk_BM_x_Int.Bytes()...)
	pk_BM = append(pk_BM, pk_BM_y_Int.Bytes()...)

	// Choose random seed
	r1, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")
	if err != nil {
		b.Fail()
	}
	r2, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")
	if err != nil {
		b.Fail()
	}
	//fmt.Println(b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ec_kem.EC_kem(c, r1, pk_BM)
		_, _ = ec_kem.EC_kem(c, r2, pk_BM)
	}
}

func BenchmarkSign(b *testing.B) {
	privA_ECDSA, _ := ec_sign.KeyGen()
	c, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")
	if err != nil {
		b.Fail()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		H.Write(c)
		H_Cr := H.Sum(nil)
		R, S := ec_sign.Sign(privA_ECDSA, H_Cr)
		_ = ec_sign.Compress_Signature(R, S)
	}
}

func BenchmarkVerify(b *testing.B) {
	// Setup
	privA_ECDSA, _ := ec_sign.KeyGen()
	privB_ECDSA, pubB_ECDSA := ec_sign.KeyGen()

	// Create ground truth
	c, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")
	if err != nil {
		b.Fail()
	}
	H := sha256.New()
	H.Write(c)
	H_c := H.Sum(nil)
	R, S := ec_sign.Sign(privB_ECDSA, H_c)

	// Create comparison such that the first will succeed, and the second will fail
	c_p := make([]byte, len(c))
	_ = copy(c_p, c)

	b.ResetTimer()
	// Simulate
	for i := 0; i < b.N; i++ {
		H = sha256.New()
		H.Write(c)
		H_rk := H.Sum(nil)
		if !bytes.Equal(c, c_p) {
			b.Fail()
		}
		if !ec_sign.Verify(pubB_ECDSA, H_rk, R, S) {
			b.Fail()
		}
		// Else block
		H = sha256.New()
		H.Write([]byte("REJECT"))
		H_msg := H.Sum(nil)
		R_msg, S_msg := ec_sign.Sign(privA_ECDSA, H_msg)
		_ = ec_sign.Compress_Signature(R_msg, S_msg)
	}
}

func BenchmarkRKA(b *testing.B) {
	h := sha256.New
	c := elliptic.P256()

	// Generate Static Pubkey of Board Member (BM)
	privBM, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")
	privBM_Int := new(big.Int)
	privBM_Int.SetBytes(privBM)

	pk_BM_x_Int, pk_BM_y_Int := c.ScalarBaseMult(privBM_Int.Bytes())

	pk_BM := make([]byte, 0)
	pk_BM = append(pk_BM, pk_BM_x_Int.Bytes()...)
	pk_BM = append(pk_BM, pk_BM_y_Int.Bytes()...)

	// Generate Static keys
	sprivA_Int, spubA_x_Int, spubA_y_Int := hmqv.GenerateKeys()
	staticKeysAlice := hmqv.StaticKeys{sprivA_Int, spubA_x_Int, spubA_y_Int}
	sprivB_Int, spubB_x_Int, spubB_y_Int := hmqv.GenerateKeys()
	staticKeysBob := hmqv.StaticKeys{sprivB_Int, spubB_x_Int, spubB_y_Int}
	privA_ECDSA, _ := ec_sign.KeyGen()
	privB_ECDSA, pubB_ECDSA := ec_sign.KeyGen()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Generate Epheremal keys of Bob
		b.StopTimer()
		eprivB_Int, epubB_x_Int, epubB_y_Int := hmqv.GenerateKeys()
		ephemeralKeysBob := hmqv.EphemeralKeys{eprivB_Int, epubB_x_Int, epubB_y_Int}
		b.StartTimer()
		// Step 1
		eprivA_Int, epubA_x_Int, epubA_y_Int := hmqv.GenerateKeys()
		ephemeralKeysAlice := hmqv.EphemeralKeys{eprivA_Int, epubA_x_Int, epubA_y_Int}
		km := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)

		r, err := ec_kem.DeriveCommitKey(h, km, 64)
		if err != nil {
			b.Fail()
		}
		r1 := r[:32]
		r2 := r[32:]

		// Step 2
		c_qk, qk := ec_kem.EC_kem(c, r1, pk_BM)
		_, rk := ec_kem.EC_kem(c, r2, pk_BM)

		// Step 3
		H := sha256.New()
		H.Write(qk)
		H_qk := H.Sum(nil)
		R, S := ec_sign.Sign(privA_ECDSA, H_qk)
		ec_sign.Compress_Signature(R, S)

		// Step 4

		// Calculate c_qk' and r_rk for Bob
		b.StopTimer()
		km_p := hmqv.Agree(&staticKeysBob, &ephemeralKeysBob, &staticKeysAlice, &ephemeralKeysAlice, false)
		Z, err := ec_kem.DeriveCommitKey(h, km_p, 64)
		if err != nil {
			b.Fail()
		}
		tau1 := Z[:32]
		tau2 := Z[32:]
		c_qk_p, _ := ec_kem.EC_kem(c, tau1, pk_BM)
		_, rk_p := ec_kem.EC_kem(c, tau2, pk_BM)
		H = sha256.New()
		H.Write(rk_p)
		H_rk_p := H.Sum(nil)
		R_rk_p, S_rk_p := ec_sign.Sign(privB_ECDSA, H_rk_p)
		b.StartTimer()

		// Step 5
		H = sha256.New()
		H.Write(rk)
		H_rk := H.Sum(nil)
		if !bytes.Equal(c_qk, c_qk_p) {
			b.Fail()
		}
		if !ec_sign.Verify(pubB_ECDSA, H_rk, R_rk_p, S_rk_p) {
			b.Fail()
		}
		// Else block
		H = sha256.New()
		H.Write([]byte("REJECT"))
		H_msg := H.Sum(nil)
		R_msg, S_msg := ec_sign.Sign(privA_ECDSA, H_msg)
		_ = ec_sign.Compress_Signature(R_msg, S_msg)
	}

}

func Test_RKA_edwards25519(t *testing.T) {
	h := sha256.New

	// Generate Static Pubkey of Board Member (BM)
	priv_BM, pub_BM, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error in GenerateKeyPair_edwards25519_()!")
	}

	// Generate Static keys
	sprivA, spubA, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysAlice := hmqv.StaticKeys_edwards25519{PrivateKey: sprivA, PublicKey: spubA}

	sprivB, spubB, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	staticKeysBob := hmqv.StaticKeys_edwards25519{PrivateKey: sprivB, PublicKey: spubB}

	// Signature Keys
	priv_A, pub_A, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error in GenerateKeyPair_edwards25519_()!")
	}

	////////////////////////////////////////////////////

	fmt.Println("* Agreed keys *")

	eprivA, epubA, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	ephemeralKeysAlice := hmqv.EphemeralKeys_edwards25519{PrivateKey: eprivA, PublicKey: epubA}

	eprivB, epubB, err := hmqv.GenerateKeyPair_edwards25519_()
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	ephemeralKeysBob := hmqv.EphemeralKeys_edwards25519{PrivateKey: eprivB, PublicKey: epubB}

	km_a, err := hmqv.Agree_edwards25519(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Alice - Km: %x\n", km_a)

	km_b, err := hmqv.Agree_edwards25519(&staticKeysBob, &ephemeralKeysBob, &staticKeysAlice, &ephemeralKeysAlice, false)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Bob - Km: %x\n", km_b)

	// Step 1

	r, err := ec_kem.DeriveCommitKey(h, km_a, 64)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Derived key (r) %x\n", r)

	r1, err := new(edwards25519.Scalar).SetBytesWithClamping(r[:32])
	if err != nil {
		t.Errorf("error in SetBytesWithClamping (unformated)- %v", err)
	}

	r2, err := new(edwards25519.Scalar).SetBytesWithClamping(r[32:])
	if err != nil {
		t.Errorf("error in SetBytesWithClamping (unformated)- %v", err)
	}

	fmt.Println("* KEM *")

	// Step 2

	Cr, Kr, err := ec_kem.EC_KEM_edwards25519(r1.Bytes(), pub_BM)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	fmt.Printf("Cr : %x\n", Cr)
	fmt.Printf("Kr : %x\n", Kr)

	Cq, Kq, err := ec_kem.EC_KEM_edwards25519(r2.Bytes(), pub_BM)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	fmt.Printf("Cq : %x\n", Cq)
	fmt.Printf("Kq : %x\n", Kq)

	fmt.Println("* DE-KEM *")

	Kr_dec, err := ec_kem.EC_DEKEM_edwards25519(priv_BM, Cr)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}

	fmt.Printf("Kr after ec_dekem: %x\n", Kr_dec)

	Kq_dec, err := ec_kem.EC_DEKEM_edwards25519(priv_BM, Cq)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	fmt.Printf("Kq after ec_dekem: %x\n", Kq_dec)

	// Step 3
	// H := sha256.New()
	// H.Write(Kq)
	// H_Kq := H.Sum(nil)

	// H := sha256.New()
	// H.Write(Kr)
	// H_Kr := H.Sum(nil)

	_priv_A := ec_sign.Format_edwards25519_priv(priv_A, pub_A)

	sigma_Cr := ec_sign.Sign_edwards25519(_priv_A, Kr)
	sigma_Cq := ec_sign.Sign_edwards25519(_priv_A, Kq)

	fmt.Printf("Signature sigma_Cr: %x\n", sigma_Cr)
	fmt.Printf("Signature sigma_Cq: %x\n", sigma_Cq)

	if !ed25519.Verify(pub_A, Kr, sigma_Cr) {
		t.Errorf("The signature sigma_Cr is not valid !")
	} else {
		fmt.Printf("The signature sigma_Cr is valid !\n")
	}

	if !ed25519.Verify(pub_A, Kq, sigma_Cq) {
		t.Errorf("The signature sigma_Cq is not valid !")
	} else {
		fmt.Printf("The signature sigma_Cq is valid !\n")
	}

}
