# 🔐 Crypto-Algorithms

  A collection of cryptographic algorithms implemented to demonstrate the fundamentals of encryption, decryption, and secure key exchange. This repository contains both [**Asymmetric**](https://en.wikipedia.org/?title=Asymmetric_cryptography&redirect=no) and [**Symmetric**](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) encryption techniques.

## Table of Contents

  - [Introduction](#introduction)
  - [Cryptographic Algorithms](#cryptographic-algorithms)
    - [Asymmetric Encryption Algorithms](#asymmetric-encryption-algorithms)
    - [Symmetric Encryption Algorithms](#symmetric-encryption-algorithms)
  - [License](#license)

---

## Introduction

  Cryptography is an essential aspect of securing digital communication. This repository provides implementations of various encryption techniques classified into:

  - [**Asymmetric Encryption Algorithms**](Asymmetric%20Encryption%20Algorithm) – Uses a pair of public and private keys for secure communication.

  - [**Symmetric Encryption Algorithms**](Symmetric%20Encryption%20Algorithm) – Uses a single key for both encryption and decryption.

  The goal is to understand how different cryptographic algorithms work and their practical implementations.



## Cryptographic Algorithms

### Asymmetric Encryption Algorithms

  | Algorithm | Description |
  |-----------|------------|
  | [Diffie-Hellman Key Exchange](Asymmetric%20Encryption%20Algorithm/Diffie-Hellman%20Key%20Exchange) | A method to securely exchange cryptographic keys over a public channel. |
  | [Rivest-Shamir-Adleman (RSA)](Asymmetric%20Encryption%20Algorithm/Rivest%20Shamir%20Adleman) | A widely used public-key cryptosystem for secure data transmission. |

### Symmetric Encryption Algorithms

  | Algorithm | Description |
  |-----------|------------|
  | [Advanced Encryption Standard (AES)](Symmetric%20Encryption%20Algorithm/Advanced%20Encryption%20Standard) | A secure and efficient encryption standard used worldwide. |
  | [Blowfish](Symmetric%20Encryption%20Algorithm/Blowfish) | A fast and flexible symmetric encryption algorithm with a variable-length key. |
  | [ChaCha20](Symmetric%20Encryption%20Algorithm/ChaCha20) | A modern stream cipher designed for high security and efficiency. |
  | [Data Encryption Standard (DES)](Symmetric%20Encryption%20Algorithm/Data%20Encryption%20Standard) | A historic symmetric-key algorithm, now considered obsolete. |
  | [RC4](Symmetric%20Encryption%20Algorithm/RC4) | A stream cipher known for its simplicity but deprecated due to vulnerabilities. |
  | [Triple DES (3DES)](Symmetric%20Encryption%20Algorithm/Triple%20DES) | An extension of DES that applies encryption three times for added security. |
  | [Twofish](Symmetric%20Encryption%20Algorithm/Twofish) | A highly secure symmetric-key algorithm that was a finalist in the AES competition. |

## License

  This repository is licensed under the Apache License 2.0.
  See the [LICENSE](./LICENSE) file for more details.


## References

  - Cryptography and Network Security by William Stallings
  - Applied Cryptography by Bruce Schneier
  - [NIST AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
  - [RFC 3526 - More Modular Exponential (MODP) Diffie-Hellman groups](https://tools.ietf.org/html/rfc3526)