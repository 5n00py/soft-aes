//! AES Encryption and Decryption in ECB Mode
//!
//! This module provides functionality for encrypting and decrypting data using
//! the Advanced Encryption Standard (AES) in Electronic Codebook (ECB) mode.
//! It includes support for optional PKCS#7 padding and 0x80 (ISO/IEC 9797-1)
//! padding,  to accommodate data that does not align with the AES block size.
//!
//! ECB mode operates on fixed-size blocks of data and is one of the simplest
//! encryption modes. While it is not recommended for encrypting large volumes
//! of data or data with patterns due to security concerns, it remains useful
//! for certain applications.
//!
//! # Features
//!
//! - `aes_enc_ecb`: Encrypts data using AES in ECB mode. It supports optional
//!   0x80 and PKCS#7 padding for data that is not a multiple of the AES block size.
//!
//! - `aes_dec_ecb`: Decrypts data that was encrypted using AES in ECB mode.
//!   It also supports the removal of 0x80 and PKCS#7 padding if it was applied
//!   during encryption.
//!
//! The implementation assumes that the provided key is of a valid length for
//! AES (128, 192, or 256 bits). The module integrates closely with the core
//! AES functionalities and the PKCS#7 padding module to offer a seamless
//! encryption/decryption experience.
//!
//! # Usage
//!
//! This module is suitable for scenarios where simple, block-wise encryption
//! and decryption are needed without the complexities of more advanced modes
//! like CBC or CTR. It is especially useful in contexts where data patterns
//! are not a concern, or where the simplicity of ECB mode is a key requirement.
//!
//! # Example
//!
//! Basic example of encrypting and decrypting data using AES-128 in ECB mode:
//!
//! ```
//! use crate::soft_aes::aes::{aes_enc_ecb, aes_dec_ecb};
//!
//! let plaintext = b"Example plaintext.";
//! let key = b"Very secret key.";
//! let padding = Some("PKCS7");
//!
//! let encrypted = aes_enc_ecb(plaintext, key, padding).expect("Encryption failed");
//! let decrypted = aes_dec_ecb(&encrypted, key, padding).expect("Decryption failed");
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! # Disclaimer
//!
//! - ECB mode does not provide serious confidentiality in many cases, as it
//!   does not use an initialization vector (IV) and encrypts identical plaintext
//!   blocks into identical ciphertext blocks. It should be used with caution,
//!   especially for encrypting data with repetitive patterns.

use super::super::padding::*;
use super::aes_core::*;

use std::error::Error;

/// Encrypt data using AES in ECB mode with optional padding.
///
/// # Parameters
/// - `plaintext`: The data to encrypt. It should be a multiple of
///                `AES_BLOCK_SIZE` unless padding is applied.
/// - `key`: The encryption key.
/// - `padding`: Optional padding method. Supported values are `None` (default),
///              `PKCS7`, and `0x80`.
///
/// # Returns
/// Returns a `Result<Vec<u8>, Box<dyn Error>>` containing the encrypted data
/// or an error.
pub fn aes_enc_ecb(
    plaintext: &[u8],
    key: &[u8],
    padding: Option<&str>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let block_size = AES_BLOCK_SIZE;
    let mut data = plaintext.to_vec();

    // Apply padding if necessary
    match padding {
        Some("PKCS7") => pkcs7_pad(&mut data, block_size)?,
        Some("0x80") => pad_80(&mut data, block_size)?,
        None if data.len() % block_size != 0 => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AES ENC ECB Error: Plaintext must be a multiple of AES_BLOCK_SIZE for 'None' padding",
            )));
        }
        _ => {}
    }

    let mut ciphertext = Vec::with_capacity(data.len());

    // Encrypt each block
    for block in data.chunks(block_size) {
        let mut block_array = [0u8; AES_BLOCK_SIZE];
        block_array.copy_from_slice(block);
        let encrypted_block = aes_enc_block(&block_array, key)?;
        ciphertext.extend_from_slice(&encrypted_block);
    }

    Ok(ciphertext)
}

/// Decrypt data using AES in ECB mode with optional padding removal.
///
/// # Parameters
/// - `ciphertext`: The encrypted data to decrypt. It should be a multiple of
///                 `AES_BLOCK_SIZE`.
/// - `key`: The decryption key.
/// - `padding`: Optional padding method used during encryption. Supported values
///              are `None` (default), `PKCS7`, and `0x80`.
///
/// # Returns
/// Returns a `Result<Vec<u8>, Box<dyn Error>>` containing the decrypted data
/// or an error.
pub fn aes_dec_ecb(
    ciphertext: &[u8],
    key: &[u8],
    padding: Option<&str>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AES DEC ECB Error: Ciphertext must be a multiple of AES_BLOCK_SIZE",
        )));
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());

    // Decrypt each block
    for block in ciphertext.chunks(AES_BLOCK_SIZE) {
        let mut block_array = [0u8; AES_BLOCK_SIZE];
        block_array.copy_from_slice(block);
        let decrypted_block = aes_dec_block(&block_array, key)?;
        plaintext.extend_from_slice(&decrypted_block);
    }

    // Remove padding if it was used during encryption
    match padding {
        Some("PKCS7") => pkcs7_unpad(&mut plaintext)?,
        Some("0x80") => unpad_80(&mut plaintext)?,
        _ => {}
    }

    Ok(plaintext)
}
