// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package main

import (
	"ardka/ec_kem"
	"ardka/ec_sign"

	"os"

	"ardka/hmqv"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type StaticKeys struct {
	privateKey  *big.Int
	publicKey_x *big.Int
	publicKey_y *big.Int
}

type EphemeralKeys struct {
	privateKey  *big.Int
	publicKey_x *big.Int
	publicKey_y *big.Int
}

func main() {

	c := elliptic.P256()
	h := sha256.New

	// Static Key Parir
	sprivA_Int, spubA_x_Int, spubA_y_Int := hmqv.GenerateKeys()

	// For already exisiting private keys use this syntax:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	// sprivA, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")
	// // Generate Static Pubkey
	// sprivA_Int := new(big.Int)
	// sprivA_Int.SetBytes(sprivA)
	// spubA_x_Int, spubA_y_Int := c.ScalarBaseMult(sprivA_Int.Bytes())
	////////////////////////////////////////////////////////////////////////////////////////////////////

	fmt.Printf("Static Pubkey A %x %x\n", spubA_x_Int, spubA_y_Int)

	// Generate Ephemeral Key Pair Generation
	eprivA_Int, epubA_x_Int, epubA_y_Int := hmqv.GenerateKeys()
	// For already exisiting private keys use this syntax:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	// eprivA, _ := hex.DecodeString("7373160a11bfaa963a35e4ca0bad8231c281c1da1153e395e9bafd38adad67bb")

	// eprivA_Int := new(big.Int)
	// eprivA_Int.SetBytes(eprivA)
	// epubA_x_Int, epubA_y_Int := c.ScalarBaseMult(eprivA_Int.Bytes())
	////////////////////////////////////////////////////////////////////////////////////////////////////
	fmt.Printf("Ephemeral Pubkey A %x %x\n", epubA_x_Int, epubA_y_Int)

	// Static Key Parir
	sprivB_Int, spubB_x_Int, spubB_y_Int := hmqv.GenerateKeys()
	////////////////////////////////////////////////////////////////////////////////////////////////////
	// sprivB, _ := hex.DecodeString("d9e3deed471b4067520d2f60b0b17a3a7b950d86ddee7a59b3fc5795db03e84f")
	// sprivB_Int := new(big.Int)
	// sprivB_Int.SetBytes(sprivB)
	// spubB_x_Int, spubB_y_Int := c.ScalarBaseMult(sprivB_Int.Bytes())
	////////////////////////////////////////////////////////////////////////////////////////////////////

	fmt.Printf("Static Pubkey B %x %x\n", spubB_x_Int, spubB_y_Int)

	// Generate Ephemeral Key Pair Generation
	eprivB_Int, epubB_x_Int, epubB_y_Int := hmqv.GenerateKeys()
	////////////////////////////////////////////////////////////////////////////////////////////////////
	// eprivB, _ := hex.DecodeString("6191a0617603aba0d5e370da6defd26c41a3020e0f502f5d40ae919bce8d0263")
	// eprivB_Int := new(big.Int)
	// eprivB_Int.SetBytes(eprivB)
	// epubB_x_Int, epubB_y_Int := c.ScalarBaseMult(eprivB_Int.Bytes())
	////////////////////////////////////////////////////////////////////////////////////////////////////
	fmt.Printf("Ephemeral Pubkey B %x %x\n", epubB_x_Int, epubB_y_Int)

	fmt.Println("*************** Test ***************")

	staticKeysAlice := hmqv.StaticKeys{sprivA_Int, spubA_x_Int, spubA_y_Int}
	ephemeralKeysAlice := hmqv.EphemeralKeys{eprivA_Int, epubA_x_Int, epubA_y_Int}

	// In a separate setting Alcice doesn't know the private keys of Bob, use PrivateKey: nil
	staticKeysBob := hmqv.StaticKeys{sprivB_Int, spubB_x_Int, spubB_y_Int}
	ephemeralKeysBob := hmqv.EphemeralKeys{eprivB_Int, epubB_x_Int, epubB_y_Int}

	fmt.Println("* Agreed keys *")

	Km1 := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)

	fmt.Printf("Km1 : %x\n", Km1) // Only the x coordinate is used from sigma_B

	Km2 := hmqv.Agree(&staticKeysBob, &ephemeralKeysBob, &staticKeysAlice, &ephemeralKeysAlice, false)

	// Km2 := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, false)
	fmt.Printf("Km2 : %x\n", Km2) // Only the x coordinate is used from sigma_B

	fmt.Println("* KEM *")

	privBM, _ := hex.DecodeString("a43c04265da1d83ff5af28f65505544ac85df6e0dcd1344ee3783cc315f3a61e")
	// Generate Static Pubkey of Board Member (BM)
	privBM_Int := new(big.Int)
	privBM_Int.SetBytes(privBM)

	pk_BM_x_Int, pk_BM_y_Int := c.ScalarBaseMult(privBM_Int.Bytes())

	pk_BM := make([]byte, 0)
	pk_BM = append(pk_BM, pk_BM_x_Int.Bytes()...)
	pk_BM = append(pk_BM, pk_BM_y_Int.Bytes()...)

	r, err := ec_kem.DeriveCommitKey(h, Km1, 64)

	r1 := r[:32]
	r2 := r[32:]

	if err != nil {
		fmt.Println("Error in deriveCommitKey")
		os.Exit(1)
	}

	fmt.Printf("r1 : %x\n", r1)
	fmt.Printf("r2 : %x\n", r2)

	Cr, Kr := ec_kem.EC_kem(c, r1, pk_BM)

	fmt.Printf("Cr : %x\n", Cr)
	fmt.Printf("Kr : %x\n", Kr)

	Cq, Kq := ec_kem.EC_kem(c, r2, pk_BM)

	fmt.Printf("Cq : %x\n", Cq)
	fmt.Printf("Kq : %x\n", Kq)

	fmt.Println("* DE-KEM *")

	Kr_dec := ec_kem.EC_dekem(c, privBM, Cr)

	fmt.Printf("Kr after ec_dekem: %x\n", Kr_dec)

	Kq_dec := ec_kem.EC_dekem(c, privBM, Cq)

	fmt.Printf("Kq after ec_dekem: %x\n", Kq_dec)

	// TODO Signature signing and verification

	privA_ECDSA, pubA_ECDSA := ec_sign.StructurizeECDSAKeys(privBM, pk_BM_x_Int, pk_BM_y_Int)

	// fmt.Printf("ECDSA keys:\n privKey : %x\npubKey_x : %x\npubKey_y : %x\n", privA_ECDSA, pubA_ECDSA.X, pubA_ECDSA.Y)

	H := sha256.New()
	H.Write(Cr)
	H_Cr := H.Sum(nil)

	R, S := ec_sign.Sign(privA_ECDSA, H_Cr)

	sigma_Cr := ec_sign.Compress_Signature(R, S)

	fmt.Printf("Signature sigma_Cr: %x\n", sigma_Cr)

	// Test verification of the signatures
	v := ec_sign.Verify(pubA_ECDSA, H_Cr, R, S)
	if v {
		fmt.Println("Valid signature")
	} else {
		fmt.Println("Not a Valid signature")
	}

	H = sha256.New()
	H.Write(Cq)
	H_Cq := H.Sum(nil)

	R, S = ec_sign.Sign(privA_ECDSA, H_Cq)

	sigma_Cq := ec_sign.Compress_Signature(R, S)

	fmt.Printf("Signature sigma_Cq: %x\n", sigma_Cq)

	// Test verification of the signatures
	v = ec_sign.Verify(pubA_ECDSA, H_Cq, R, S)
	if v {
		fmt.Println("Valid signature")
	} else {
		fmt.Println("Not a Valid signature")
	}

	//////////////////////////////////////////////////////////////////
	// Bob does the same signature process with his private key	   //
	////////////////////////////////////////////////////////////////

	// TODO send sigma_Cr and sigma_Cq to the blockchain

}
