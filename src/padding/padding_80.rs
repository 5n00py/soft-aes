//! 0x80 Padding Module (ISO/IEC 9797-1 Padding Method 2)
//!
//! This module provides functionality for applying and removing 0x80 padding
//! to and from byte arrays, aligning with ISO/IEC 9797-1 padding method 2.
//! This padding scheme is commonly used in cryptographic protocols and involves
//! appending a byte with the value 0x80 (binary 1000 0000) followed by as many
//! zero bytes (0x00) as needed to fill the last block to a specified block size.
//!
//! This method ensures that the padded message is always of a length that is a
//! multiple of the block size, which is crucial for block cipher operations in
//! cryptographic algorithms. The distinct 0x80 byte guarantees that the padding
//! is unambiguous, ensuring reliable padding removal.
//!
//! # Features
//!
//! - `pad_80`: Applies 0x80 padding to a byte array, extending its size to a multiple
//!   of the specified block size.
//!
//! - `unpad_80`: Removes 0x80 padding from a byte array, reverting it to its original
//!   unpadded state.
//!
//! # Usage
//!
//! This padding scheme is particularly useful in cryptographic applications where
//! the input data size must align with the block size of a block cipher algorithm,
//! such as AES. It can be employed in various scenarios, including encryption and
//! message authentication code (MAC) generation.
//!
//! # Examples
//!
//! Basic usage examples demonstrating padding and unpadding a byte array:
//!
//! ```
//! use soft_aes::padding::{pad_80, unpad_80};
//!
//! let mut data = vec![0x01, 0x02, 0x03];
//! let block_size = 8;
//! pad_80(&mut data, block_size).expect("Padding failed");
//!
//! // Data is now padded according to ISO/IEC 9797-1 Padding Method 2
//! assert_eq!(data, vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]);
//!
//! unpad_80(&mut data).expect("Unpadding failed");
//!
//! // Data is back to its original form
//! assert_eq!(data, vec![0x01, 0x02, 0x03]);
//! ```
//!
//! # References
//!
//! - ISO/IEC 9797-1: Information technology – Security techniques – Message Authentication Codes (MACs) –
//!   Part 1: Mechanisms using a block cipher
//!
//! # Disclaimer
//!
//! - This implementation focuses on clarity and correctness as per ISO/IEC 9797-1 Padding Method 2.
//!   For high-performance requirements, additional optimizations may be necessary.

use std::error::Error;

/// Apply 0x80 padding to a given byte array, in-place.
///
/// This function pads the input byte array so that its length is a multiple of
/// the specified block size. The padding starts with a single 0x80 byte followed
/// by 0x00 bytes.
///
/// # Arguments
///
/// * `data` : A mutable reference to the byte array (`Vec<u8>`) to be padded.
/// * `block_size` : The block size (`usize`) for padding.
///
/// # Returns
///
/// * `Ok(())` if the padding is successfully applied.
/// * `Err(Box<dyn Error>)` if the block size is invalid.
pub fn pad_80(data: &mut Vec<u8>, block_size: usize) -> Result<(), Box<dyn Error>> {
    if block_size == 0 {
        return Err("0x80 PADDING ERROR: Block size must be greater than 0".into());
    }

    data.push(0x80);

    while data.len() % block_size != 0 {
        data.push(0x00);
    }

    Ok(())
}

/// Remove 0x80 padding from a given byte array, in-place.
///
/// This function removes the 0x80 padding from the provided byte array.
/// It checks for the presence of 0x80 followed by 0x00 bytes and removes them.
///
/// # Arguments
///
/// * `data` : A mutable reference to the byte array (`Vec<u8>`) from which
///            padding is to be removed.
///
/// # Returns
///
/// * `Ok(())` if the unpadding is successfully performed.
/// * `Err(Box<dyn Error>)` if there's an issue with the padding.
pub fn unpad_80(data: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    if let Some(position) = data.iter().rposition(|&x| x == 0x80) {
        if data[position + 1..].iter().all(|&x| x == 0x00) {
            data.truncate(position);
            Ok(())
        } else {
            Err("0x80 UNPADDING ERROR: Invalid padding".into())
        }
    } else {
        Err("0x80 UNPADDING ERROR: Padding byte not found".into())
    }
}
