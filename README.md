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

## Disclaimer

- **ECB Mode Limitations:** The ECB (Electronic Codebook) mode of AES does not
  ensure confidentiality for data with recognizable patterns. Consequently, its
  use should be limited to specific cases where data patterns are not a
  concern.
  
- **CBC Mode Considerations:** While AES CBC (Cipher Block Chaining) mode
  significantly enhances security over ECB mode, it requires careful management
  of the Initialization Vector (IV). IVs should be random and unique for each
  encryption session to maintain security.

- **Cryptographic Randomness:** This library does not include its own
  cryptographic random number generators. Users should ensure the use of proper
  cryptographic random number generators, especially when generating keys and
  IVs for cryptographic operations.

- **Key Management:** Effective key management practices are essential for
  maintaining security. This library does not manage or store cryptographic
  keys. Users are responsible for managing keys securely, including their
  generation, storage, and destruction.

- **No Protection Against Side-Channel Attacks:** The current implementation of
  this library does not include specific countermeasures against side-channel
  attacks. It is intended primarily for educational use and non-critical
  applications where side-channel resistance is not a primary concern.

- **"As Is" Provision:** The library is provided "as is," without any warranty
  of any kind. The developers are not liable for any consequences arising from
  the use or misuse of this library. Users are encouraged to assess the
  suitability of this library for their intended applications.

This disclaimer aims to highlight critical areas of cryptographic practice that
are beyond the scope of this library but are nonetheless integral to the secure
deployment of cryptographic algorithms.

## Official Standard References

- AES is defined in [FIPS PUB 197](https://csrc.nist.gov/pubs/fips/197/final).

- PKCS#7 padding is defined in [RFC
  2315](https://www.rfc-editor.org/rfc/rfc2315).

## Acknowledgments

The development of the Soft-AES library is a culmination of knowledge,
resources, and tools that have significantly influenced its design and
implementation. This section extends gratitude to various contributions and
inspirations that have shaped the library.

The Rust implementation of Soft-AES is fundamentally based on a C
implementation I implemented during my studies, primarily guided by the book "The
Design of Rijndael" and its reference code. The updated insights from "The
Design of Rijndael: AES - The Advanced Encryption Standard" by Joan Daemen and
Vincent Rijmen.

A notable modification in the Rust implementation, compared to the original C
version, is the key expansion routine. In the Rust library, the key expansion
is executed directly on a byte buffer, adhering to the (MAX_ROUNDS+1)x4x4 array
structure traditionally specified in AES documentation. This adjustment
reflects suggestions from other C implementations and is optimized for
efficiency within the Rust context.

Further Assistance:

- AI Assistance: In documenting, commenting, and troubleshooting aspects of the
  library, AI tools have played a supportive role. Their use has been
  particularly valuable in ensuring clarity, coherence, and consistency in the
  library's documentation.

- [SmartCommit](https://github.com/5n00py/SmartCommit): The development process
  has been augmented with the use of SmartCommit, a semi-automated tool for
  generating commit messages. This tool has enhanced the efficiency and
  consistency of the development workflow, ensuring that each change is
  accurately and comprehensively documented.

## Contributing

Contributions to the Soft-AES library are welcome. Please ensure that your code
adheres to the existing style and that all tests pass.

## License

This project is licensed under the GNU General Public License Version 3
(GPLv3), as detailed in the [LICENSE](LICENSE) file.
