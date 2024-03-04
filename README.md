# ARDKA


## Auditable, Recoverable and Distributed Key Agreement for Medical Data Sharing

This is a Golang implementation of our Auditable, Recoverable and Distributed Key Agreement for Medical Data Sharing (ARDKA) protocol. The protocl combines HMQV, EC-KEM and ECDSA protocols.


## Dependence 

The implementation uses the standard and supplementary Go cryptography libraries.

To use our implementation the `golang.org/x/crypto` is also required. To get `golang.org/x/crypto` please library use:

```bash 
go get -u golang.org/x/crypto 
```

## How to Use ?

Some notes: the protocol is run between two parties Alice and Bob. 
Alice has `(a,A)` - static (longterm) private/public key pair and she generates `(x,X)` Ephemeral key for each session of communication.
Bob has `(b,B)` - static (longterm) private/public key pair and he generates `(y,Y)` Ephemeral key for each session of communication.

To note: `\hat{B}` and ` \hat{A}` are the static public keys.


By running:

```bash 
go run ardka.go
```

To note, the HMQV protocol is executed among the two parties:
```bash 
Agree(staticKeys *StaticKeys, ephemeralKeys *EphemeralKeys, staticOtherKeys *StaticKeys, ephemeralOtherKeys *EphemeralKeys, role bool)
```
when role is set to `True`: 
```bash
sigma_A = (Y . B^{e})^{x + d.a mod q}
```

when role is set to `False` the protocol computes: 
```bash
sigma_B}=(X \cdot A^{d})^{y + e.b mod q }
```

To run it only at one parties side just uncomment one of the following lines:
```bash
Km1 := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
Km2 := hmqv.Agree(&staticKeysBob, &ephemeralKeysBob, &staticKeysAlice, &ephemeralKeysAlice, false)
```

To note: when only one party will be run, the private key of the other party is unknown, therefore, it can be set to `nil`. For exemple when only Alice runs the HMQV protocol the following call can be applied:
```bash
Km1 := hmqv.Agree(&staticKeysAlice, &ephemeralKeysAlice, nil, &ephemeralKeysBob, true)
```

## Test HMQV and EC_KEM modules
As these two modules are the main building blocks of our protocol, they are also available separately and they can be tested in main() functions.
These two modules are under `\test_blocks` folder.  