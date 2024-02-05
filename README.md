# Soft-AES: A Software-Based Functional AES Library in Rust

**Soft-AES** is a Rust library offering a software-based implementation of the
Advanced Encryption Standard (AES) algorithm, distinct from hardware-based
solutions. It provides AES encryption and decryption in Electronic Codebook
(ECB) and Cipher Block Chaining (CBC) modes and an integrated Cipher-based
Message Authentication Code (AES-CMAC) calculation.

The library includes support for PKCS#7 padding and `0x80` padding (ISO/IEC
9797-1 Padding Method 2).

AES functionalities in Soft-AES are implemented using a functional approach, as
opposed to instance-based approaches. By employing lookup tables for critical
AES operations, the library achieves a balance between simplicity and
performance.

**HAZMAT!** It's important to recognize that this implementation does not
currently incorporate defenses against side-channel attacks. Consequently,
Soft-AES is optimally suited for educational purposes and non-critical
application scenarios like testing where advanced protections are not a primary
concern.

## Table of Contents

- [Features](#features)
- [Usage](#usage)
  - [AES ECB Mode](#aes-ecb-mode)
  - [AES CBC Mode](#aes-cbc-mode)
  - [PKCS#7 Padding](#pkcs7-padding)
  - [0x80 Padding](#0x80-padding)
- [Testing](#testing)
  - [Current NIST Test Coverage](#current-nist-test-coverage)
  - [Core Unit Tests](#core-unit-tests)
  - [Future Test Expansion](#future-test-expansion)
- [Disclaimer](#disclaimer)
- [Official Standard References](#official-standard-references)
- [Acknowledgments](#acknowledgments)
- [Related Projects](#related-projects)
  - [soft-aes-wasm](#soft-aes-wasm)
  - [Web UI for AES Encryption/Decryption](#web-ui-for-aes-encryptiondecryption)
- [Contributing](#contributing)
- [License](#license)

## Features

- **AES Core:** Core implementations for encryption and decryption processes of
  a single block, including SubBytes, ShiftRows, MixColumns, and their
  inverses.
- **ECB Mode:** Simple block-wise encryption and decryption without chaining.
- **CBC Mode:** Improved block-wise encryption and decryption with
  Initialization Vector (IV) based chaining.
- **AES-CMAC:** Message authentication capabilities based on AES-128.
- **PKCS#7 Padding:** Support for PKCS#7 padding scheme to ensure uniform block
  sizes.
- **0x80 Padding:** Support for `0x80` padding (ISO/IEC 9797-1 Padding Method
  2).

## Usage

To use `soft-aes` in your Rust project, add it as a dependency in your
`Cargo.toml` file:

```toml
[dependencies]
soft-aes = "0.2.0"
```

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

The Soft-AES library includes comprehensive testing against the National
Institute of Standards and Technology (NIST) Advanced Encryption Standard
Algorithm Validation Suite (AESAVS) for ECB mode and additional test vectors.

### Current NIST Test Coverage

- **AES ECB Mode Validation:** Extensive coverage utilizing Known Answer Tests
  (KAT) from the AESAVS for various key sizes.

### Core Unit Tests

Additional tests using test vectors from CryptoTool's Online AES Step-by-Step
Tool.

### Future Test Expansion

Plans to expand test coverage for other AES modes and additional test
scenarios.

## Disclaimer

- **ECB Mode Limitations:** The ECB mode of AES does not ensure confidentiality
  for data with recognizable patterns.
- **CBC Mode Considerations:** While AES CBC mode enhances security, it
  requires careful management of the Initialization Vector (IV).
- **Cryptographic Randomness and Key Management:** The library does not include
  its own cryptographic random number generators or manage cryptographic
  keys.
- **No Protection Against Side-Channel Attacks:** Intended primarily for
  educational use and non-critical applications.
- **"As Is" Provision:** The library is provided "as is," without any
  warranty.

## Official Standard References

- AES is defined in [FIPS PUB 197](https://csrc.nist.gov/pubs/fips/197/final).

- AES-CMAC is defined in [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493).

- PKCS#7 padding is defined in [RFC
  2315](https://www.rfc-editor.org/rfc/rfc2315).

## Acknowledgments

The development of the Soft-AES library is a culmination of knowledge,
resources, and tools that have significantly influenced its design and
implementation.

The Rust implementation of Soft-AES is fundamentally based on a C
implementation I implemented during my studies, primarily guided by the book
"The Design of Rijndael" and its reference code. The updated insights from "The
Design of Rijndael: AES - The Advanced Encryption Standard" by Joan Daemen and
Vincent Rijmen.

Furthermore AI assistance was used in documenting, commenting and
troubleshooting aspects of the library and
[SmartCommit](https://github.com/5n00py/SmartCommit) as commit assistant.

## Related Projects

### soft-aes-wasm 

[soft-aes-wasm](https://github.com/5n00py/soft-aes-wasm) is a
companion project that extends the functionality of the `Soft-AES` library to
WebAssembly (Wasm). This project enables AES encryption and
decryption directly in web applications by providing a Wasm interface for
`Soft-AES`.

### Web UI for AES Encryption/Decryption

For a practical and user-friendly implementation of AES directly in the
browser, visit [AES-Wasm Tool](https://jointech.at/tools/aes-wasm/index.html).
This web tool based on `soft-aes-wasm` library provides a convenient solution
for performing AES encryption and decryption tests in the browser.

## License

Copyright David Schmid (david.schmid@mailbox.org)

Binaries are subject to the terms of the GNU General Public License Version 3
(GPLv3), as detailed in the [LICENSE](LICENSE) file.
