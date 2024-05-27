package main

import (
	"ardka/ec_kem"
	"ardka/ec_sign"
	"ardka/hmqv"
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
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
	privA_ECDSA, pubA_ECDSA := ec_sign.KeyGen()

	// Create ground truth
	c, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d7")
	if err != nil {
		b.Fail()
	}
	H := sha256.New()
	H.Write(c)
	H_c := H.Sum(nil)
	R, S := ec_sign.Sign(privA_ECDSA, H_c)

	// Create comparison such that the first will succeed, and the second will fail
	c_p := make([]byte, 0)
	_ = copy(c_p, c)
	l, err := hex.DecodeString("fefcb63981a0ead2fcae71c63c7ea4917b67f57db1b79bb109bf862da35975d8")
	if err != nil {
		b.Fail()
	}

	b.ResetTimer()
	// Simulate
	for i := 0; i < b.N; i++ {
		H = sha256.New()
		H.Write(l)

		if bytes.Equal(c_p, c) && ec_sign.Verify(pubA_ECDSA, H_c, R, S) {
			b.Fail()
		} else {
			H := sha256.New()
			H.Write(c)
			H_Cr := H.Sum(nil)
			R, S := ec_sign.Sign(privA_ECDSA, H_Cr)
			_ = ec_sign.Compress_Signature(R, S)
		}
	}
}

func BenchmarkAKE(b *testing.B) {
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
