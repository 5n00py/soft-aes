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
