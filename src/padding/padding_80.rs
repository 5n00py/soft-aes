//! 0x80 Padding Module
//!
//! This module provides functionality for applying and removing 0x80 padding
//! to and from byte arrays. The padding scheme appends a single 0x80 byte
//! followed by 0x00 bytes until the data length aligns with a specified block size.

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
