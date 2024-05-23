package main

import (
	"ardka/ec_kem"
	"ardka/ec_sign"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ec_kem.EC_kem(c, r1, pk_BM)
		_, _ = ec_kem.EC_kem(c, r2, pk_BM)
	}
}

func BenchmarkStep3(b *testing.B) {
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
