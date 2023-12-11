//! AES Encryption and Decryption in CBC Mode
//!
//! This module provides functionality for encrypting and decrypting data using
//! the Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC) mode.
//! It includes support for optional padding, specifically PKCS#7 padding, to
//! accommodate data that does not align with the AES block size.
//!
//! CBC mode is more secure than ECB mode as it uses an initialization vector (IV)
//! to add randomness to the encryption process and chains the blocks together,
//! ensuring identical plaintext blocks encrypt to different ciphertext blocks.
//!
//! # Features
//!
//! - `aes_enc_cbc`: Encrypts data using AES in CBC mode. It supports optional
//!   PKCS#7 padding for data that is not a multiple of the AES block size.
//!
//! - `aes_dec_cbc`: Decrypts data that was encrypted using AES in CBC mode.
//!   It also supports the removal of PKCS#7 padding if it was applied during
//!   encryption.
//!
//! The implementation requires both an encryption key and an initialization
//! vector (IV) of valid lengths for AES (128, 192, or 256 bits for the key,
//! and 128 bits for the IV). This module closely integrates with the core AES
//! functionalities and the PKCS#7 padding module to offer a comprehensive
//! encryption/decryption experience.
//!
//! # Usage
//!
//! CBC mode is recommended for encrypting data of any significant length,
//! especially where data patterns may be present. It provides stronger security
//! guarantees compared to ECB mode due to the usage of an IV and block chaining.
//!
//! # Example
//!
//! Basic example of encrypting and decrypting data using AES-128 in CBC mode:
//!
//! ```
//! use crate::soft_aes::aes::{aes_enc_cbc, aes_dec_cbc};
//!
//! let plaintext = b"Example plaintext.";
//! let key = b"Very secret key.";
//! let iv = b"Random Init Vec."; // 16 bytes IV for AES-128
//! let padding = Some("PKCS7");
//!
//! let encrypted = aes_enc_cbc(plaintext, key, iv, padding).expect("Encryption failed");
//! let decrypted = aes_dec_cbc(&encrypted, key, iv, padding).expect("Decryption failed");
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! # Disclaimer
//!
//! - While CBC mode adds significant security improvements over ECB mode, it is
//!   still crucial to use it correctly. IV must be random and unique for each
//!   encryption operation to maintain security. Additionally, it is important to
//!   understand that CBC mode itself does not provide authentication or integrity
//!   checks; these should be implemented separately if needed.

use super::super::padding::*;
use super::aes_core::*;

/// Encrypt data using AES in CBC mode with optional padding.
///
/// # Parameters
/// - `plaintext`: The data to encrypt. It should be a multiple of
///                `AES_BLOCK_SIZE` unless PKCS7 padding is applied.
/// - `key`: The encryption key.
/// - `iv`: The initialization vector (IV) for CBC mode.
/// - `padding`: Optional padding method. Supported values are `None` (default)
///              and `PKCS7`.
///
/// # Returns
/// Returns a `Result<Vec<u8>, Box<dyn std::error::Error>>` containing the
/// encrypted data or an error.
pub fn aes_enc_cbc(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    padding: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let block_size = AES_BLOCK_SIZE;
    let mut data = plaintext.to_vec();

    // Apply padding if necessary
    if let Some("PKCS7") = padding {
        pkcs7_pad(&mut data, block_size)?;
    } else if data.len() % block_size != 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AES ENC CBC Error: Plaintext must be a multiple of AES_BLOCK_SIZE for 'None' padding",
        )));
    }

    let mut ciphertext = Vec::with_capacity(data.len());
    let mut previous_block = iv.clone();

    // Encrypt each block
    for block in data.chunks(block_size) {
        let mut block_array = [0u8; AES_BLOCK_SIZE];
        block_array.copy_from_slice(block);

        // XOR current block with previous ciphertext block (or IV for first block)
        for (b, p) in block_array.iter_mut().zip(previous_block.iter()) {
            *b ^= *p;
        }

        let encrypted_block = aes_enc_block(&block_array, key)?;
        previous_block = encrypted_block;
        ciphertext.extend_from_slice(&previous_block);
    }

    Ok(ciphertext)
}

/// Decrypt data using AES in CBC mode with optional padding removal.
///
/// # Parameters
/// - `ciphertext`: The encrypted data to decrypt. It should be a multiple of
///                 `AES_BLOCK_SIZE`.
/// - `key`: The decryption key.
/// - `iv`: The initialization vector (IV) used during encryption for CBC mode.
/// - `padding`: Optional padding method used during encryption. Supported value
///              is `PKCS7` for removing padding after decryption.
///
/// # Returns
/// Returns a `Result<Vec<u8>, Box<dyn std::error::Error>>` containing the
/// decrypted data or an error.
pub fn aes_dec_cbc(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    padding: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AES DEC CBC Error: Ciphertext must be a multiple of AES_BLOCK_SIZE",
        )));
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut previous_block = iv.clone();

    // Decrypt each block
    for block in ciphertext.chunks(AES_BLOCK_SIZE) {
        let mut block_array = [0u8; AES_BLOCK_SIZE];
        block_array.copy_from_slice(block);

        let mut decrypted_block = aes_dec_block(&block_array, key)?;
        // XOR decrypted block with previous ciphertext block (or IV for first block)
        for (b, p) in decrypted_block.iter_mut().zip(previous_block.iter()) {
            *b ^= *p;
        }

        plaintext.extend_from_slice(&decrypted_block);
        previous_block.copy_from_slice(block);
    }

    // Remove PKCS7 padding if it was used during encryption
    if let Some("PKCS7") = padding {
        pkcs7_unpad(&mut plaintext)?;
    }

    Ok(plaintext)
}
