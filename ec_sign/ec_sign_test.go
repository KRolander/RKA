package ec_sign

import (
	"ardka/hmqv"
	"crypto/ed25519"
	"fmt"
	"testing"
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

// func TestSign_Verfy_edwards25519(t *testing.T) {
// 	// In RFC 8032 the private key is 32 bytes, in crypto/edwards this value corresponds to the seed

// 	var privKeyBytes [32]byte
// 	_, _ = io.ReadFull(rand.Reader, privKeyBytes[:])

// 	privateKey, err := new(edwards25519.Scalar).SetBytesWithClamping(privKeyBytes[:])
// 	if err != nil {
// 		t.Errorf("TSetBytesWithClamping!")
// 	}

// 	fmt.Printf("Private Key : %x\n", privKeyBytes)

// 	sprivA := privateKey.Bytes()
// 	priv_ed := ed25519.NewKeyFromSeed(sprivA)
// 	pub_ed := priv_ed.Public().(ed25519.PublicKey)

// 	fmt.Printf("pub_ed : %x\n", pub_ed)

// 	priv_ed_2 := ed25519.NewKeyFromSeed(privKeyBytes[:])

// 	fmt.Printf("Private key 2 : %x\n", priv_ed_2)

// 	pub_ed_2 := priv_ed_2.Public().(ed25519.PublicKey)

// 	fmt.Printf("pub_ed_2 : %x\n", pub_ed_2)

// 	hash := sha512.New()
// 	hashLen := 32
// 	hash.Write(sprivA)

// 	_digest := hash.Sum(nil)

// 	pub_digest := _digest[:hashLen]

// 	fmt.Printf("pub_digest : %x\n", pub_digest)

// 	climped_hash_scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(pub_digest)
// 	if err != nil {
// 		t.Errorf("error in SetBytesWithClamping (e)- %v", err)
// 	}

// 	pub := new(edwards25519.Point).ScalarBaseMult(climped_hash_scalar)

// 	fmt.Printf("pub: %x\n", pub.Bytes())

// 	hash = sha512.New()
// 	hash.Write(privKeyBytes[:])

// 	_digest_2 := hash.Sum(nil)

// 	pub_digest_2 := _digest_2[:hashLen]

// 	fmt.Printf("pub_digest : %x\n", pub_digest)
// 	fmt.Printf("pub_digest_2 : %x\n", pub_digest_2)

// 	climped_hash_scalar_2, err := new(edwards25519.Scalar).SetBytesWithClamping(pub_digest_2)
// 	if err != nil {
// 		t.Errorf("error in SetBytesWithClamping (e)- %v", err)
// 	}

// 	pub_2 := new(edwards25519.Point).ScalarBaseMult(climped_hash_scalar_2)

// 	fmt.Printf("pub_2: %x\n", pub_2.Bytes())

// 	// sprivA, spubA, err := hmqv.GenerateKeyPair_edwards25519()
// 	// if err != nil {
// 	// 	t.Errorf("Error: %v\n", err)
// 	// }

// 	message := []byte("Hello World")

// 	// // RFC 8032 key is used to create a private key
// 	// priv_ed := ed25519.NewKeyFromSeed(sprivA)

// 	// fmt.Printf("sprivA : %x\n", sprivA)
// 	// fmt.Printf("priv_ed.Seed() : %x\n", priv_ed.Seed())
// 	// fmt.Printf("priv_ed : %x\n", priv_ed)

// 	// pub_ed := priv_ed.Public().(ed25519.PublicKey)

// 	// fmt.Printf("pub_ed : %x\n", pub_ed)

// 	// hash := sha512.New()
// 	// hashLen := 32
// 	// hash.Write(priv_ed.Seed())

// 	// _digest := hash.Sum(nil)

// 	// pub_digest := _digest[:hashLen]

// 	// fmt.Printf("pub_digest : %x\n", pub_digest)

// 	// pub_digest_calpped, err := new(edwards25519.Scalar).SetBytesWithClamping(pub_digest)
// 	// if err != nil {
// 	// 	t.Errorf("SetBytesWithClamping!")
// 	// }
// 	// fmt.Printf("pub_digest - calmped : %x\n", pub_digest_calpped.Bytes())

// 	// fmt.Printf("spubA : %x\n", spubA)
// 	// fmt.Printf("spubA BytesMontgomery : %x\n", pub.BytesMontgomery())

// 	signature := ed25519.Sign(priv_ed, message)
// 	signature_2 := ed25519.Sign(priv_ed_2, message)

// 	// fmt.Printf("Signature : %x\n", signature)

// 	// // Verify if the signature was issued by the the public key pair - spubA

// 	if !ed25519.Verify(pub.Bytes(), message, signature) {
// 		t.Errorf("The signature is not valid !")
// 	} else {
// 		fmt.Printf("The signature is valid !\n")
// 	}

// 	if !ed25519.Verify(pub_2.Bytes(), message, signature_2) {
// 		t.Errorf("The signature_2 is not valid !")
// 	} else {
// 		fmt.Printf("The signature_2 is valid !\n")
// 	}

// }
