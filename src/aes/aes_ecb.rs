use super::super::padding::*;
use super::aes_core::*;

/// Encrypt data using AES in ECB mode with optional padding.
///
/// # Parameters
/// - `plaintext`: The data to encrypt. It should be a multiple of
///                `AES_BLOCK_SIZE` unless PKCS7 padding is applied.
/// - `key`: The encryption key.
/// - `padding`: Optional padding method. Supported values are `None` (default)
///              and `PKCS7`.
///
/// # Returns
/// Returns a `Result<Vec<u8>, Box<dyn std::error::Error>>` containing the
/// encrypted data or an error.
pub fn aes_enc_ecb(
    plaintext: &[u8],
    key: &[u8],
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
            "AES ENC ECB Error: Plaintext must be a multiple of AES_BLOCK_SIZE for 'None' padding",
        )));
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
