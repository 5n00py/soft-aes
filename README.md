# Soft-AES: A Software-Based Functional AES Library in Rust

**Soft-AES** is a Rust library that offers a software-based implementation of
the Advanced Encryption Standard (AES) algorithm, distinct from hardware-based
solutions. It provides AES encryption and decryption in various modes. The AES
functionalities are implemented using a functional approach, as opposed to
instance-based approaches. By employing lookup tables for critical AES
operations, it offers a balance between simplicity and performance.

It's important to recognize that this implementation currently does not
incorporate defenses against side-channel attacks. Consequently, Soft-AES is
optimally positioned for educational purposes and non-critical application
scenarios where such advanced protections are not a primary concern.

Additionally, the library includes support for PKCS#7 padding, making it
suitable for a range of cryptographic applications.

## Features

- **AES Core:** Core implementations for both encryption and decryption
  processes of a single block, along with auxiliary functions like SubBytes,
  ShiftRows, MixColumns, and their inverses.

- **ECB Mode:** Simple block-wise encryption and decryption without chaining.

- **CBC Mode:** More secure block-wise encryption and decryption with
  Initialization Vector (IV) based chaining.

- **PKCS#7 Padding:** Support for PKCS#7 padding scheme to ensure uniform block
  sizes for encryption and decryption.


