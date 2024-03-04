// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

func main() {
	rng := blake2xb.New(nil)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	a_suite := suite.Scalar().Pick(rng)        // Alice's private key
	A_suite := suite.Point().Mul(a_suite, nil) // Alice's public key

	fmt.Printf("A_suite %v\n", A_suite)

	c := elliptic.P256()

	// Static Key Parir Generation TODO -> random generation
	sprivA, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")

	// Generate Static Pubkey
	sprivA_Int := new(big.Int)
	sprivA_Int.SetBytes(sprivA)
	spubA_x_Int, spubA_y_Int := c.ScalarBaseMult(sprivA_Int.Bytes())

	fmt.Printf("Static Pubkey A %x %x\n", spubA_x_Int, spubA_y_Int)

	// Generate Ephemeral Key Pair Generation

	eprivA, _ := hex.DecodeString("7373160a11bfaa963a35e4ca0bad8231c281c1da1153e395e9bafd38adad67bb")

	eprivA_Int := new(big.Int)
	eprivA_Int.SetBytes(eprivA)
	epubA_x_Int, epubA_y_Int := c.ScalarBaseMult(eprivA_Int.Bytes())

	fmt.Printf("Ephemeral Pubkey A %x %x\n", epubA_x_Int, epubA_y_Int)

	sprivB, _ := hex.DecodeString("d9e3deed471b4067520d2f60b0b17a3a7b950d86ddee7a59b3fc5795db03e84f")

	// Generate Static Pubkey
	sprivB_Int := new(big.Int)
	sprivB_Int.SetBytes(sprivB)
	spubB_x_Int, spubB_y_Int := c.ScalarBaseMult(sprivB_Int.Bytes())

	fmt.Printf("Static Pubkey B %x %x\n", spubB_x_Int, spubB_y_Int)

	// Generate Ephemeral Key Pair Generation

	eprivB, _ := hex.DecodeString("6191a0617603aba0d5e370da6defd26c41a3020e0f502f5d40ae919bce8d0263")

	eprivB_Int := new(big.Int)
	eprivB_Int.SetBytes(eprivB)
	epubB_x_Int, epubB_y_Int := c.ScalarBaseMult(eprivB_Int.Bytes())

	fmt.Printf("Ephemeral Pubkey B %x %x\n", epubB_x_Int, epubB_y_Int)

	// Alice

	// a := sprivA_Int
	// A_x, A_y := c.ScalarBaseMult(a.Bytes())

	A := []byte{0x4}

	A = append(A, spubA_x_Int.Bytes()...)
	A = append(A, spubA_y_Int.Bytes()...)

	Y := []byte{0x4}
	Y = append(Y, epubB_x_Int.Bytes()...)
	Y = append(Y, epubB_y_Int.Bytes()...)

	// Bob

	B := []byte{0x4}

	B = append(B, spubB_x_Int.Bytes()...)
	B = append(B, spubB_y_Int.Bytes()...)

	X := []byte{0x4}
	X = append(X, epubA_x_Int.Bytes()...)
	X = append(X, epubA_y_Int.Bytes()...)

	e := HMQV_Hash(nil, Y, A, "sha256")
	fmt.Printf("hmqv_e : %x\n", e)

	d := HMQV_Hash(nil, X, B, "sha256")
	fmt.Printf("hmqv_d : %x\n", d)

	// d := make([]byte, 0)
	// e := make([]byte, 0)

	// fmt.Printf("X = %x len(X) = %d\n", X, len(X))
	// fmt.Printf("B = %x len(B) = %d\n", B, len(B))

	// Compute $d = \hat{H}(X, \hat{B})$

	// sha_256_d := sha256.New()
	// sha_256_d.Write(X)
	// sha_256_d.Write(B)

	// _d := sha_256_d.Sum(nil)

	// d := _d[:16]
	// // Compute $e = \hat{H}(Y, \hat{A})$

	// sha_256_e := sha256.New()
	// sha_256_e.Write(Y)
	// sha_256_e.Write(A)

	// _e := sha_256_e.Sum(nil)
	// e := _e[:16]

	// fmt.Printf("d : %x\n", d)
	// fmt.Printf("e : %x\n", e)

	q := c.Params().N

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	y := eprivB_Int
	b := sprivB_Int

	e_Int := new(big.Int)

	e_Int.SetBytes(e)

	e_mult_b := new(big.Int)

	e_mult_b.Mul(e_Int, b)

	y_add_e_mult_b := new(big.Int)
	y_add_e_mult_b.Add(y, e_mult_b)

	s_B := new(big.Int)

	// s_B = y + e.b mod q

	s_B.Mod(y_add_e_mult_b, q)

	fmt.Printf("s_B : %x\n", s_B)

	// $\sigma_B}=(X \cdot A^{d})^{s_B} -- server

	A_pow_dx, A_pow_dy := c.ScalarMult(spubA_x_Int, spubA_y_Int, d)

	X_mul_Ax, X_mul_Ay := c.Add(epubA_x_Int, epubA_y_Int, A_pow_dx, A_pow_dy)

	sigma_Bx, sigma_By := c.ScalarMult(X_mul_Ax, X_mul_Ay, s_B.Bytes())

	fmt.Printf("sigma_B : %x %x\n", sigma_Bx, sigma_By) // Only the x coordinate is used from sigma_B

	sigma_B_hash := sha256.New()
	sigma_B_hash.Write(sigma_Bx.Bytes())
	K_B := sigma_B_hash.Sum(nil)
	fmt.Printf("K : %x\n", K_B) // Only the x coordinate is used from sigma_B

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	x := eprivA_Int
	a := sprivA_Int

	d_Int := new(big.Int)

	d_Int.SetBytes(d)

	d_mult_a := new(big.Int)

	d_mult_a.Mul(d_Int, a)

	x_add_d_mult_a := new(big.Int)
	x_add_d_mult_a.Add(x, d_mult_a)

	s_A := new(big.Int)
	s_A.Mod(x_add_d_mult_a, q)

	fmt.Printf("s_A : %x\n", s_A)

	// $\sigma_A}=(Y \cdot B^{e})^{s_A}

	B_pow_ex, B_pow_ey := c.ScalarMult(spubB_x_Int, spubB_y_Int, e)

	Y_mul_Bx, Y_mul_By := c.Add(epubB_x_Int, epubB_y_Int, B_pow_ex, B_pow_ey)

	sigma_Ax, sigma_Ay := c.ScalarMult(Y_mul_Bx, Y_mul_By, s_A.Bytes())

	fmt.Printf("sigma_A : %x %x\n", sigma_Ax, sigma_Ay) // Only the x coordinate is used from sigma_B

	sigma_A_hash := sha256.New()
	sigma_A_hash.Write(sigma_Ax.Bytes())
	K_A := sigma_A_hash.Sum(nil)
	fmt.Printf("K : %x\n", K_A) // Only the x coordinate is used from sigma_B

	//  Hash(NULLPTR, XX, xxs, BB, bbs, dd.BytePtr(), dd.SizeInBytes());
	//  Integer d(dd.BytePtr(), dd.SizeInBytes());

}

// To compute d = H(X, \hat{B}) or e = H(Y, \hat{A}) the sigma must be nil; half of the hash digests returned
// To compute sigma -> ephpub = nil ; statpub = nil -> only x coordinate of sigma is requiered as input -> entier hash digests returned
func HMQV_Hash(sigma []byte, ephpub []byte, statpub []byte, hashType string) []byte {

	var h hash.Hash
	var hashLen int

	switch hashType {
	case "sha256":
		h = sha256.New()
		hashLen = 16
	case "sha512":
		h = sha512.New()
		hashLen = 32
	}

	if sigma != nil {
		// K = H(sigma)
		h.Write(sigma)
		hashLen = 32
	} else {
		// d = H(X, \hat{B}) and e = H(Y, \hat{A})

		h.Write(ephpub)  // X or Y
		h.Write(statpub) // \hat{B}) or \hat{A})

	}

	_digest := h.Sum(nil)

	digest := _digest[:hashLen]

	return digest
}

// role : true -> Alice | false -> Bob

func Agree(staticPrivateKey []byte, ephemeralPrivateKey []byte, staticOtherPublicKey []byte, ephemeralOtherPublicKey []byte, role bool) []byte {

	// Alice
	if role == true {

	} else {
		// Bob

	}

	return nil
}

// Bob
