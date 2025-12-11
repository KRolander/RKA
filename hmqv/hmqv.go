// Authors: R. Kromes (REIT Team) & J. van Assen (Cybersecurity group)
// TU Delft Cybersecurity group 2024

package hmqv

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"

	"filippo.io/edwards25519"
)

type StaticKeys struct {
	PrivateKey  *big.Int
	PublicKey_x *big.Int
	PublicKey_y *big.Int
}

type EphemeralKeys struct {
	PrivateKey  *big.Int
	PublicKey_x *big.Int
	PublicKey_y *big.Int
}

type StaticKeys_edwards25519 struct {
	PrivateKey []byte
	PublicKey  []byte
}

type EphemeralKeys_edwards25519 struct {
	PrivateKey []byte
	PublicKey  []byte
}

func KeyGen() {

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
// func Agree(staticPrivateKey []byte, staticPublicKey []byte, ephemeralPrivateKey []byte, ephemeralPublicKey []byte, staticOtherPublicKey []byte, ephemeralOtherPublicKey []byte, role bool) []byte {
func Agree(staticKeys *StaticKeys, ephemeralKeys *EphemeralKeys, staticOtherKeys *StaticKeys, ephemeralOtherKeys *EphemeralKeys, role bool) []byte {
	c := elliptic.P256()

	q := c.Params().N

	K := make([]byte, 0)
	// Alice
	if role {

		sprivA_Int := staticKeys.PrivateKey
		spubA_x_Int := staticKeys.PublicKey_x
		spubA_y_Int := staticKeys.PublicKey_y

		A := []byte{0x4}
		A = append(A, spubA_x_Int.Bytes()...)
		A = append(A, spubA_y_Int.Bytes()...)

		eprivA_Int := ephemeralKeys.PrivateKey

		epubA_x_Int := ephemeralKeys.PublicKey_x
		epubA_y_Int := ephemeralKeys.PublicKey_y

		X := []byte{0x4}
		X = append(X, epubA_x_Int.Bytes()...)
		X = append(X, epubA_y_Int.Bytes()...)

		// B is normally known in advance - Y is exchanged
		spubB_x_Int := staticOtherKeys.PublicKey_x
		spubB_y_Int := staticOtherKeys.PublicKey_y

		B := []byte{0x4}

		B = append(B, spubB_x_Int.Bytes()...)
		B = append(B, spubB_y_Int.Bytes()...)

		epubB_x_Int := ephemeralOtherKeys.PublicKey_x
		epubB_y_Int := ephemeralOtherKeys.PublicKey_y

		Y := []byte{0x4}
		Y = append(Y, epubB_x_Int.Bytes()...)
		Y = append(Y, epubB_y_Int.Bytes()...)

		// Check the validity of the static and ephemeral public keys of Bob
		err := isValidPublicKey(c, spubB_x_Int, spubB_y_Int)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		err = isValidPublicKey(c, epubB_x_Int, epubB_y_Int)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		e := HMQV_Hash(nil, Y, A, "sha256")
		// fmt.Printf("hmqv_e : %x\n", e)

		d := HMQV_Hash(nil, X, B, "sha256")
		// fmt.Printf("hmqv_d : %x\n", d)

		x := eprivA_Int
		a := sprivA_Int

		d_Int := new(big.Int)

		d_Int.SetBytes(d)

		d_mult_a := new(big.Int)

		d_mult_a.Mul(d_Int, a)

		x_add_d_mult_a := new(big.Int)
		x_add_d_mult_a.Add(x, d_mult_a)

		// s_A = x + d.a mod q

		s_A := new(big.Int)
		s_A.Mod(x_add_d_mult_a, q)

		// fmt.Printf("s_A : %x\n", s_A)

		// $\sigma_A}=(Y \cdot B^{e})^{s_A}

		B_pow_ex, B_pow_ey := c.ScalarMult(spubB_x_Int, spubB_y_Int, e)

		Y_mul_Bx, Y_mul_By := c.Add(epubB_x_Int, epubB_y_Int, B_pow_ex, B_pow_ey)

		sigma_Ax, _ := c.ScalarMult(Y_mul_Bx, Y_mul_By, s_A.Bytes())

		// fmt.Printf("sigma_A : %x %x\n", sigma_Ax, sigma_Ay) // Only the x coordinate is used from sigma_B

		K = HMQV_Hash(sigma_Ax.Bytes(), nil, nil, "sha256")

	} else {
		// Bob

		sprivB_Int := staticKeys.PrivateKey
		spubB_x_Int := staticKeys.PublicKey_x
		spubB_y_Int := staticKeys.PublicKey_y

		B := []byte{0x4}

		B = append(B, spubB_x_Int.Bytes()...)
		B = append(B, spubB_y_Int.Bytes()...)

		eprivB_Int := ephemeralKeys.PrivateKey
		epubB_x_Int := ephemeralKeys.PublicKey_x
		epubB_y_Int := ephemeralKeys.PublicKey_y

		Y := []byte{0x4}
		Y = append(Y, epubB_x_Int.Bytes()...)
		Y = append(Y, epubB_y_Int.Bytes()...)

		// A is normally known in advance - X is exchanged

		spubA_x_Int := staticOtherKeys.PublicKey_x
		spubA_y_Int := staticOtherKeys.PublicKey_y

		A := []byte{0x4}

		A = append(A, spubA_x_Int.Bytes()...)
		A = append(A, spubA_y_Int.Bytes()...)

		epubA_x_Int := ephemeralOtherKeys.PublicKey_x
		epubA_y_Int := ephemeralOtherKeys.PublicKey_y

		X := []byte{0x4}
		X = append(X, epubA_x_Int.Bytes()...)
		X = append(X, epubA_y_Int.Bytes()...)

		// Check the validity of the static and ephemeral public keys of Alice
		err := isValidPublicKey(c, spubA_x_Int, spubA_y_Int)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		err = isValidPublicKey(c, epubA_x_Int, epubA_y_Int)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		e := HMQV_Hash(nil, Y, A, "sha256")
		// fmt.Printf("hmqv_e : %x\n", e)

		d := HMQV_Hash(nil, X, B, "sha256")
		// fmt.Printf("hmqv_d : %x\n", d)

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

		// fmt.Printf("s_B : %x\n", s_B)

		// $\sigma_B}=(X \cdot A^{d})^{s_B} -- server

		A_pow_dx, A_pow_dy := c.ScalarMult(spubA_x_Int, spubA_y_Int, d)

		X_mul_Ax, X_mul_Ay := c.Add(epubA_x_Int, epubA_y_Int, A_pow_dx, A_pow_dy)

		sigma_Bx, _ := c.ScalarMult(X_mul_Ax, X_mul_Ay, s_B.Bytes())

		// fmt.Printf("sigma_B : %x %x\n", sigma_Bx, sigma_By) // Only the x coordinate is used from sigma_B

		K = HMQV_Hash(sigma_Bx.Bytes(), nil, nil, "sha256")

	}

	return K
}

// Verifies if the public key is valid (generated in the given Finite field)
func isValidPublicKey(c elliptic.Curve, PublicKey_x *big.Int, PublicKey_y *big.Int) error {

	if !c.IsOnCurve(PublicKey_x, PublicKey_y) {
		return errors.New("The public key's point does not lie on the curve ")
	}

	if PublicKey_x.Sign() == 0 && PublicKey_y.Sign() == 0 {
		return errors.New("The public key point is at infinity")
	}

	return nil
}

// Returns private key (as *big.Int), public key x and y coordinates (as *big.Int, *big.Int)
func GenerateKeys() (*big.Int, *big.Int, *big.Int) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return privateKey.D, privateKey.X, privateKey.Y

}

// RFC-8032 scalar creation
// The 'unformated' is 32 octets (256 bits).
// Hash the 32-byte 'unformated' using SHA-512, storing the digest in a 64-octet large buffer, denoted h.
// SetBytesWithClamping() applies the appies buffer pruning
func Construct_RFC8032_Scalar(unformated []byte) (*edwards25519.Scalar, error) {
	hashLen := 32

	hash := sha512.New()
	hash.Write(unformated)
	digests := hash.Sum(nil)

	digests_32 := digests[:hashLen]

	climped_digests_32, err := new(edwards25519.Scalar).SetBytesWithClamping(digests_32)
	if err != nil {
		return nil, fmt.Errorf("error in SetBytesWithClamping (unformated)- %v", err)
	}

	return climped_digests_32, nil
}

// HMQV protocol based on Edwards255199
// This version is an extension of our library since the Agree() function uses elliptic curve arithmetics from cypto/elliptic whihc are depricated - not safe agains timing attacks
// Edwards25519 arithmetics from filippo.io/edwards25519 are computed in constant time making it safe agains timing attacks
func Agree_edwards25519(staticKeys *StaticKeys_edwards25519, ephemeralKeys *EphemeralKeys_edwards25519, staticOtherKeys *StaticKeys_edwards25519, ephemeralOtherKeys *EphemeralKeys_edwards25519, role bool) ([]byte, error) {

	K := make([]byte, 0)

	// Alice

	if role {
		sprivA := staticKeys.PrivateKey
		A := staticKeys.PublicKey

		eprivA := ephemeralKeys.PrivateKey
		X := ephemeralKeys.PublicKey

		B_bytes := staticOtherKeys.PublicKey
		Y_bytes := ephemeralOtherKeys.PublicKey

		B, err := new(edwards25519.Point).SetBytes(B_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytes - %v", err)
		}

		Y, err := new(edwards25519.Point).SetBytes(Y_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytes - %v", err)
		}

		e_bytes := HMQV_Hash(nil, Y.Bytes(), A, "sha512")

		d_bytes := HMQV_Hash(nil, X, B.Bytes(), "sha512")

		e, err := new(edwards25519.Scalar).SetBytesWithClamping(e_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytesWithClamping (e)- %v", err)
		}

		d, err := new(edwards25519.Scalar).SetBytesWithClamping(d_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (d)- %v", err)
		}

		x, err := Construct_RFC8032_Scalar(eprivA)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (x)- %v", err)
		}

		a, err := Construct_RFC8032_Scalar(sprivA)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (a)- %v", err)
		}
		//Compute s_A = x + d.a mod I

		// s_A := new(edwards25519.Scalar).MultiplyAdd(d, a, x) // s = x * y + z mod l

		d_x_a := new(edwards25519.Scalar).Multiply(d, a)

		s_A := new(edwards25519.Scalar).Add(d_x_a, x)
		//Compute $\sigma_A}=(Y \cdot B^{e})^{s_A}

		// B^e
		B_pow_e := new(edwards25519.Point).ScalarMult(e, B)

		// Y \cdot B^{e} -> Y + B^e since \cdot == add on an ellipic curve
		Y_mul_B_pow_e := new(edwards25519.Point).Add(Y, B_pow_e)

		sigma_A := new(edwards25519.Point).ScalarMult(s_A, Y_mul_B_pow_e)

		K = HMQV_Hash(sigma_A.Bytes(), nil, nil, "sha256")

	} else {
		// Bob

		sprivB := staticKeys.PrivateKey
		B := staticKeys.PublicKey

		eprivB := ephemeralKeys.PrivateKey
		Y := ephemeralKeys.PublicKey

		// A is normally known in advance - X is exchanged
		A_bytes := staticOtherKeys.PublicKey
		X_bytes := ephemeralOtherKeys.PublicKey

		A, err := new(edwards25519.Point).SetBytes(A_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytes - %v", err)
		}

		X, err := new(edwards25519.Point).SetBytes(X_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytes - %v", err)
		}

		e_bytes := HMQV_Hash(nil, Y, A.Bytes(), "sha512")

		d_bytes := HMQV_Hash(nil, X.Bytes(), B, "sha512")

		e, err := new(edwards25519.Scalar).SetBytesWithClamping(e_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetBytesWithClamping (e)- %v", err)
		}

		d, err := new(edwards25519.Scalar).SetBytesWithClamping(d_bytes)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (d)- %v", err)
		}

		y, err := Construct_RFC8032_Scalar(eprivB)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (x)- %v", err)
		}

		b, err := Construct_RFC8032_Scalar(sprivB)
		if err != nil {
			return nil, fmt.Errorf("error in SetCanonicalBytes (b)- %v", err)
		}

		//Compute s_B = y + e.b mod I

		// s_B := new(edwards25519.Scalar).MultiplyAdd(e, b, y) // s = x * y + z mod l

		e_x_b := new(edwards25519.Scalar).Multiply(e, b)

		s_B := new(edwards25519.Scalar).Add(e_x_b, y)

		//Compute {\sigma_B}=(X \cdot A^{d})^{s_B} -- server

		// A^d
		A_pow_d := new(edwards25519.Point).ScalarMult(d, A)

		// X \cdot A^{d} -> X + A^d since \cdot == add on an ellipic curve
		X_mul_A_pow_d := new(edwards25519.Point).Add(X, A_pow_d)

		sigma_B := new(edwards25519.Point).ScalarMult(s_B, X_mul_A_pow_d)

		K = HMQV_Hash(sigma_B.Bytes(), nil, nil, "sha256")

	}
	return K, nil
}

// Returns an Edwards25519 private and publick key
// the publick key is compressed to 32 byte format
// Key generation follows RFC-8032
func GenerateKeyPair_edwards25519() ([]byte, []byte, error) {
	var privKeyBytes [32]byte
	_, _ = io.ReadFull(rand.Reader, privKeyBytes[:])

	privateKey, err := new(edwards25519.Scalar).SetBytesWithClamping(privKeyBytes[:])
	if err != nil {
		return nil, nil, err
	}

	priv_bytes := privateKey.Bytes()

	hash := sha512.New()
	hashLen := 32
	hash.Write(priv_bytes)

	hash_digest := hash.Sum(nil)

	priv_key_hash := hash_digest[:hashLen]

	climped_hash_scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(priv_key_hash)
	if err != nil {
		return nil, nil, err
	}

	pub := new(edwards25519.Point).ScalarBaseMult(climped_hash_scalar)

	return priv_bytes, pub.Bytes(), nil

}

// Returns an Edwards25519 private and publick key
// the publick key is compressed to 32 byte format
// This function is equivalent of GenerateKeyPair_edwards25519(), but it might be safer
// sicne it uses inbuilt libraries to generate the key pair
// Key generation follows RFC-8032
func GenerateKeyPair_edwards25519_() ([]byte, []byte, error) {

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return priv.Seed(), priv.Public().(ed25519.PublicKey), nil

}
