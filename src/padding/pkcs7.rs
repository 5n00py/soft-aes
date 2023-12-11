//! PKCS#7 Padding and Unpadding Module
//!
//! This module provides functionality for applying and removing PKCS#7 padding
//! to and from byte arrays. PKCS#7 padding, defined in the PKCS#7 (Public Key
//! Cryptography Standards #7) standard by RSA Laboratories, is commonly used
//! in various cryptographic algorithms to ensure that data blocks are of a
//! uniform size.
//!
//! The PKCS#7 standard defines a padding scheme that appends a set of bytes to
//! the end of a data block. Each byte of the padding is set to the same value,
//! which is equal to the number of padding bytes added. This module implements
//! two primary functions:
//!
//! - `pkcs7_pad`: Applies PKCS#7 padding to a given byte array (`Vec<u8>`),
//!   ensuring that its length is a multiple of a specified block size. The
//!   function adds padding in place and is designed to be efficient and
//!   straightforward to use.
//!
//! - `pkcs7_unpad`: Removes PKCS#7 padding from a given byte array (`Vec<u8>`),
//!   verifying the consistency and correctness of the padding before removal.
//!   This function also modifies the data in place and ensures that the
//!   unpadding operation is secure and reliable.
//!
//! # Usage
//!
//! The module is designed to be easily integrated into cryptographic
//! applications, particularly those involving block ciphers where data blocks
//! need to be a specific size. The padding and unpadding operations are
//! essential in scenarios where data must be encrypted and decrypted in a
//! manner consistent with PKCS#7 standards.
//!
//! # Examples
//!
//! Basic usage examples demonstrating padding and unpadding a byte array:
//!
//! ```
//! use soft_aes::padding::{pkcs7_pad, pkcs7_unpad};
//!
//! let mut data = vec![0x01, 0x02, 0x03];
//! let block_size = 8;
//! pkcs7_pad(&mut data, block_size).expect("Padding failed");
//!
//! // Data is now padded according to PKCS#7
//! assert_eq!(data, vec![0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05]);
//!
//! pkcs7_unpad(&mut data).expect("Unpadding failed");
//!
//! // Data is back to its original form
//! assert_eq!(data, vec![0x01, 0x02, 0x03]);
//! ```
//!
//! # Official Standard Reference
//!
//! - The PKCS#7 padding scheme is defined in the PKCS#7 standard, which is part
//!   of the Public Key Cryptography Standards series. The standard is detailed
//!   in the document "PKCS #7: Cryptographic Message Syntax Version 1.5",
//!   paragraph 10.3. "Content-encryption process":
//!   [https://www.rfc-editor.org/rfc/rfc2315](https://www.rfc-editor.org/rfc/rfc2315).
//!
//! # Note
//!
//! - The implementation focuses on clarity and correctness of the PKCS#7
//!   standard. It's suitable for educational and straightforward practical
//!   applications. For high-performance requirements, further optimizations
//!   may be necessary.

use std::error::Error;

/// Apply PKCS#7 padding to a given byte array, in-place.
///
/// This function pads the input byte array so that its length is a multiple of
/// the specified block size, according to the PKCS#7 padding scheme. The
/// padding bytes added are all the same value, equal to the number of bytes
/// added. If the input length is already a multiple of the block size, an
/// entire block of padding is added.
///
/// # Arguments
///
/// * `data` : A mutable reference to the byte array (`Vec<u8>`) to be padded.
///            The data is manipulated directly, adding padding in place.
/// * `block_size` : The block size (`usize`) for padding. Must be greater than
///                  0 and less than 256.
///
/// # Returns
///
/// * `Ok(())` if the padding is successfully applied,
/// * `Err(Box<dyn Error>)` if the block size is invalid (0 or >= 256).
pub fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) -> Result<(), Box<dyn Error>> {
    if block_size == 0 || block_size >= 256 {
        return Err(
            "PKCS7 PADDING ERROR: Block size must be greater than 0 and less than 256".into(),
        );
    }

    let padding_size = block_size - (data.len() % block_size);
    let padding_byte = padding_size as u8;

    for _ in 0..padding_size {
        data.push(padding_byte);
    }

    Ok(())
}

/// Remove PKCS#7 padding from a given byte array, in-place.
///
/// This function inspects and removes the PKCS#7 padding from the provided
/// byte array. It checks the value of the last byte of the array (which
/// indicates the padding size), verifies that the padding is consistent, and
/// then removes the padding bytes.
///
/// # Arguments
///
/// * `data` : A mutable reference to the byte array (`Vec<u8>`) from which
///            padding is to be removed. The data is manipulated directly, with
///            padding bytes being removed in place.
///
/// # Returns
///
/// * `Ok(())` if the unpadding is successfully performed,
/// * `Err(Box<dyn Error>)` if there's an issue with the padding (e.g.,
///    inconsistent padding bytes, invalid padding size, or empty input data).
pub fn pkcs7_unpad(data: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    if data.is_empty() {
        return Err("PKCS7 UNPADDING ERROR: Input data is empty".into());
    }

    let padding_byte = *data
        .last()
        .ok_or("PKCS7 UNPADDING ERROR: Unable to get the last byte")?
        as usize;

    // Check if padding_byte is within valid range (1 to data.len())
    if padding_byte == 0 || padding_byte > data.len() {
        return Err("PKCS7 UNPADDING ERROR: Invalid padding".into());
    }

    // Verify that all the padding bytes are the same
    if data
        .iter()
        .rev()
        .take(padding_byte)
        .any(|&x| x as usize != padding_byte)
    {
        return Err("PKCS7 UNPADDING ERROR: Padding bytes are not consistent".into());
    }

    // Remove the padding bytes
    data.truncate(data.len() - padding_byte);

    Ok(())
}
