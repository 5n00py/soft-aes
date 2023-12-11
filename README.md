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

## Testing

The Soft-AES library includes a comprehensive test suite for validating its
implementation against the [National Institute of Standards and Technology
(NIST) Advanced Encryption Standard Algorithm Validation Suite
(AESAVS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf).
These tests are crucial in ensuring that the AES implementation aligns with the
established standards and recommendations provided by NIST.

### Current NIST Test Coverage

- **AES ECB Mode Validation:** The current test suite extensively covers the
  AES Electronic Codebook (ECB) mode. It utilizes Known Answer Tests (KAT) from
  the AESAVS, focusing on various key sizes (128, 192, and 256 bits) and
  assessing both encryption and decryption capabilities.

The tests verify the correctness of the implementation against fixed plaintexts
with varying keys and varying plaintexts with fixed keys.

### Core Unit Tests

In addition to the NIST AESAVS-based tests, the library also employs a set of
core unit tests utilizing test vectors from [CryptoTool's Online AES
Step-by-Step Tool](https://www.cryptool.org/en/cto/aes-step-by-step). This
resource provides a detailed breakdown of the AES algorithm's steps, making it
an invaluable tool for understanding and debugging the AES implementation.

### Future Test Expansion

- **Additional AES Modes:** Plans are in place to expand the test suite to
  cover other AES modes, such as Cipher Block Chaining (CBC) and others,
  aligning with the AESAVS guidelines and ensuring comprehensive validation
  across different AES operational modes. 
- Further Test Scenarios: Additional tests will be incorporated to cover a
  wider range of scenarios and corner cases, thereby enhancing the reliability
  and robustness of the library. The ongoing development of the test suite is a
  critical component of maintaining the high standards of cryptographic
  reliability and compliance with NIST guidelines. Contributions and
  suggestions for additional tests or improvements are always welcome.


