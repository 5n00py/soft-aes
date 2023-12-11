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
