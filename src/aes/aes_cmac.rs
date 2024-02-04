//! AES-CMAC (Cipher-based Message Authentication Code) Implementation
//!
//! This module provides functionality for computing the AES-CMAC, a message authentication code
//! based on AES and the CMAC algorithm, as specified in RFC 4493. AES-CMAC is designed to provide
//! stronger assurance of data integrity than traditional checksums or error-detecting codes,
//! effectively detecting both accidental and intentional unauthorized data modifications.
//!
//! AES-CMAC is based on the Advanced Encryption Standard (AES) and is equivalent to the One-Key
//! CBC MAC1 (OMAC1), an improvement over eXtended Cipher Block Chaining mode (XCBC) and the basic
//! Cipher Block Chaining-Message Authentication Code (CBC-MAC). This algorithm achieves a security
//! goal similar to HMAC but uses AES, making it more appropriate in systems where AES is more
//! readily available than hash functions.
//!
//! The implementation focuses on AES-CMAC with a 128-bit key (AES-128), providing a secure method
//! to authenticate messages. It is particularly useful in scenarios where data integrity and
//! authenticity are of high importance and where AES is a preferred choice over hash-based MACs
//! like HMAC.
//!
//! # Features
//!
//! - `aes_cmac`: Computes the AES-CMAC for a given message and a 128-bit AES key.
//!
//! - `generate_subkey`: Generates subkeys used in the CMAC algorithm from a given AES key.
//!
//! # Usage
//!
//! AES-CMAC is suitable for various cryptographic applications, especially in systems where AES is
//! preferred or more efficient than hash functions. It provides strong authentication and is
//! simpler to implement in environments where AES is already available.
//!
//! # Example
//!
//! Compute the AES-CMAC for a specific message and key as per RFC 4493 test vector:
//!
//! ```
//! use crate::soft_aes::aes::aes_cmac;
//! use hex::decode as hex_decode;
//!
//! // Key and message are given in hexadecimal format
//! let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
//! let message = hex_decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
//!
//! let mac = aes_cmac(&message, &key).unwrap();
//!
//! // The resulting MAC should match the specified test vector
//! assert_eq!(
//!     mac.to_vec(),
//!     hex_decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap()
//! );
//! ```
//!
//! This example uses the `hex_decode` function from the `hex` crate to convert the hexadecimal strings
//! into byte arrays for the key and message. The resulting MAC is then compared against the expected value
//! from the test vector.
//!
//! # References
//!
//! - RFC 4493: The AES-CMAC Algorithm
//!   [https://www.rfc-editor.org/rfc/rfc4493]
//! - NIST Publication on Recommendation for Key Derivation: [https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final]
//! - Related cryptographic standards: OMAC1, XCBC, CBC-MAC
//!
//! # Disclaimer
//!
//! - While AES-CMAC provides strong data integrity assurance, it is important to use it
//!   correctly. Ensure that keys are securely managed and never reused across different
//!   security contexts.
//!
//! - This implementation aims for clarity and adherence to the standard. For high-performance
//!   requirements, further optimizations may be necessary.
use super::aes_core::*;
use crate::padding::pad_80;

use std::error::Error;

const CONST_ZERO: [u8; 16] = [0; 16];
const CONST_RB: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87];

/// Generate subkeys for AES-CMAC.
///
/// # Parameters
/// - `key`: The 128-bit AES key.
///
/// # Returns
/// Returns a tuple of two 128-bit subkeys `(K1, K2)`.
pub fn generate_subkey(key: &[u8]) -> Result<([u8; 16], [u8; 16]), Box<dyn Error>> {
    // Step 1: L := AES-128(K, const_Zero)
    let l = aes_enc_block(&CONST_ZERO, key)?;

    // Step 2: Generate K1
    let mut k1 = left_shift_one_bit(&l);
    if l[0] & 0x80 != 0 {
        // if MSB(L) == 1
        for (k1_byte, rb_byte) in k1.iter_mut().zip(CONST_RB.iter()) {
            *k1_byte ^= rb_byte;
        }
    }

    // Step 3: Generate K2
    let mut k2 = left_shift_one_bit(&k1);
    if k1[0] & 0x80 != 0 {
        // if MSB(K1) == 1
        for (k2_byte, rb_byte) in k2.iter_mut().zip(CONST_RB.iter()) {
            *k2_byte ^= rb_byte;
        }
    }

    Ok((k1, k2))
}

/// Compute AES-CMAC for a given message using a specified key.
///
/// AES-CMAC is a message authentication code based on AES and CMAC (Cipher-based MAC).
/// This function calculates the MAC (Message Authentication Code) using the AES-128
/// algorithm in CMAC mode as per the specification in RFC 4493.
///
/// # Arguments
///
/// * `message` - The message for which to compute the MAC.
/// * `key` - The 128-bit AES key.
///
/// # Returns
///
/// A `Result` containing the computed MAC as a 128-bit array if successful, or an error.
///
/// # Errors
///
/// Returns an error if any cryptographic operation fails or the key is not 16 bytes long.
pub fn aes_cmac(message: &[u8], key: &[u8]) -> Result<[u8; 16], Box<dyn Error>> {
    // Check if the key length is 16 bytes (128 bit)
    if key.len() != 16 {
        return Err("ERROR AES-CMAC: The key must be exactly 128 bits (16 bytes) long".into());
    }

    // Step 1: Generate the subkeys K1 and K2.
    let (k1, k2) = generate_subkey(key)?;

    // Step 2: Determine the number of blocks n.
    let n = if message.is_empty() {
        1
    } else {
        (message.len() + 15) / 16
    };
    let flag = message.len() % 16 == 0;

    // Step 3 & 4: Prepare the last block (m_last) for MAC processing.
    let mut m_last = [0u8; 16];
    if flag && !message.is_empty() {
        // If the message is not empty and the last block is complete
        m_last.copy_from_slice(&message[16 * (n - 1)..]);
        xor_with_subkey(&mut m_last, &k1); // XOR with K1
    } else {
        // If the message is empty or the last block is not complete
        let mut last_block = if message.is_empty() {
            Vec::new()
        } else {
            message[16 * (n - 1)..].to_vec()
        };
        pad_80(&mut last_block, 16)?; // Apply the padding
        m_last.copy_from_slice(&last_block);
        xor_with_subkey(&mut m_last, &k2); // XOR with K2
    }

    // Step 5 & 6: Perform the AES-CMAC algorithm.
    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&message[16 * i..16 * (i + 1)]);
        x = xor(&x, &block); // XOR with each block
        x = aes_enc_block(&x, key)?; // Encrypt with AES
    }

    let y = xor(&m_last, &x); // XOR with the last block
    let t = aes_enc_block(&y, key)?; // Final AES encryption to produce the MAC

    Ok(t)
}

/// Helper function to XOR a block with a subkey.
fn xor_with_subkey(block: &mut [u8; 16], subkey: &[u8; 16]) {
    for (b, k) in block.iter_mut().zip(subkey.iter()) {
        *b ^= k;
    }
}

/// XOR two 128-bit blocks.
fn xor(block1: &[u8; 16], block2: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = block1[i] ^ block2[i];
    }
    result
}

/// Perform a left bitwise shift by one bit on a 16-byte array.
fn left_shift_one_bit(input: &[u8]) -> [u8; 16] {
    let mut output = [0u8; 16];
    let mut overflow = 0;

    for &byte in input.iter().rev() {
        output.rotate_right(1);
        output[0] = byte << 1 | overflow;
        overflow = (byte >> 7) & 1;
    }

    output
}
