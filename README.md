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

## Usage

This library is designed for straightforward integration into cryptographic
applications, especially those requiring AES encryption and decryption. Below
are basic usage examples for different components of the library.

### AES ECB Mode

```rust 
use soft_aes::aes::{aes_enc_ecb, aes_dec_ecb};

let plaintext = b"Example plaintext."; 
let key = b"Very secret key."; 
let padding = Some("PKCS7");

let encrypted = aes_enc_ecb(plaintext, key, padding).expect("Encryption failed");
let decrypted = aes_dec_ecb(&encrypted, key, padding).expect("Decryption failed");

assert_eq!(decrypted, plaintext);
```

### AES CBC Mode

```rust
use soft_aes::aes::{aes_enc_cbc, aes_dec_cbc};

let plaintext = b"Example plaintext.";
let key = b"Very secret key.";
let iv = b"Random Init Vec.";
let padding = Some("PKCS7");

let encrypted = aes_enc_cbc(plaintext, key, iv, padding).expect("Encryption failed");
let decrypted = aes_dec_cbc(&encrypted, key, iv, padding).expect("Decryption failed");

assert_eq!(decrypted, plaintext);
```

### PKCS#7 Padding

```rust
use soft_aes::padding::{pkcs7_pad, pkcs7_unpad};

let mut data = vec![0x01, 0x02, 0x03];
let block_size = 8;
pkcs7_pad(&mut data, block_size).expect("Padding failed");
assert_eq!(data, vec![0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05]);

pkcs7_unpad(&mut data).expect("Unpadding failed");
assert_eq!(data, vec![0x01, 0x02, 0x03]);
```


