use super::super::aes_cbc::*;

use hex;

#[test]
fn test_aes_enc_cbc_no_padding() {
    // Define the plaintext, key, IV, and expected ciphertext as byte arrays
    let plaintext: [u8; 16] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ];
    let key: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let iv: [u8; 16] = [
        0xfe, 0x5b, 0xf0, 0x4a, 0x23, 0x1c, 0xa7, 0x79, 0x5a, 0xee, 0x7e, 0xc2, 0xe4, 0x3b, 0x14,
        0x4a,
    ];
    let expected_ciphertext: [u8; 16] = [
        0xf8, 0x3b, 0x59, 0x5b, 0x49, 0x0a, 0x74, 0x64, 0xee, 0xa1, 0x64, 0x4a, 0xfb, 0x31, 0xb5,
        0x2e,
    ];

    // Call the AES CBC encryption function
    let ciphertext = aes_enc_cbc(&plaintext, &key, &iv, None).expect("Encryption failed");

    // Assert that the produced ciphertext matches the expected ciphertext
    assert_eq!(
        ciphertext.as_slice(),
        expected_ciphertext.as_slice(),
        "Ciphertext does not match expected value"
    );
}

#[test]
fn test_aes_enc_cbc_with_pkcs7_padding() {
    // Define the plaintext, key, IV, and expected ciphertext as byte arrays
    let plaintext: [u8; 20] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    let key: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let iv: [u8; 16] = [
        0xfe, 0x5b, 0xf0, 0x4a, 0x23, 0x1c, 0xa7, 0x79, 0x5a, 0xee, 0x7e, 0xc2, 0xe4, 0x3b, 0x14,
        0x4a,
    ];
    let expected_ciphertext: Vec<u8> = vec![
        0x42, 0x64, 0x9c, 0x72, 0xf6, 0x0f, 0xf9, 0x14, 0x48, 0xdb, 0x75, 0x86, 0x2f, 0xe2, 0x78,
        0x85, 0x14, 0xe8, 0xa5, 0xe6, 0x92, 0x70, 0xf2, 0xc3, 0x7a, 0x62, 0xcf, 0x70, 0x06, 0x18,
        0x7a, 0xea,
    ];

    // Call the AES CBC encryption function with PKCS#7 padding
    let ciphertext = aes_enc_cbc(&plaintext, &key, &iv, Some("PKCS7")).expect("Encryption failed");

    // Assert that the produced ciphertext matches the expected ciphertext
    assert_eq!(
        ciphertext, expected_ciphertext,
        "Ciphertext does not match expected value"
    );
}

#[test]
fn test_aes_dec_cbc_no_padding() {
    // Define the expected plaintext, key, IV, and ciphertext as byte arrays
    let expected_plaintext: [u8; 16] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ];
    let key: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let iv: [u8; 16] = [
        0xfe, 0x5b, 0xf0, 0x4a, 0x23, 0x1c, 0xa7, 0x79, 0x5a, 0xee, 0x7e, 0xc2, 0xe4, 0x3b, 0x14,
        0x4a,
    ];
    let ciphertext: [u8; 16] = [
        0xf8, 0x3b, 0x59, 0x5b, 0x49, 0x0a, 0x74, 0x64, 0xee, 0xa1, 0x64, 0x4a, 0xfb, 0x31, 0xb5,
        0x2e,
    ];

    // Call the AES CBC decryption function
    let plaintext = aes_dec_cbc(&ciphertext, &key, &iv, None).expect("Decryption failed");

    // Assert that the produced plaintext matches the expected plaintext
    assert_eq!(
        plaintext.as_slice(),
        expected_plaintext.as_slice(),
        "Plaintext does not match expected value"
    );
}

#[test]
fn test_aes_dec_cbc_with_pkcs7_padding() {
    // Define the expected plaintext, key, IV, and ciphertext as byte arrays
    let expected_plaintext: [u8; 20] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    let key: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let iv: [u8; 16] = [
        0xfe, 0x5b, 0xf0, 0x4a, 0x23, 0x1c, 0xa7, 0x79, 0x5a, 0xee, 0x7e, 0xc2, 0xe4, 0x3b, 0x14,
        0x4a,
    ];
    let ciphertext: Vec<u8> = vec![
        0x42, 0x64, 0x9c, 0x72, 0xf6, 0x0f, 0xf9, 0x14, 0x48, 0xdb, 0x75, 0x86, 0x2f, 0xe2, 0x78,
        0x85, 0x14, 0xe8, 0xa5, 0xe6, 0x92, 0x70, 0xf2, 0xc3, 0x7a, 0x62, 0xcf, 0x70, 0x06, 0x18,
        0x7a, 0xea,
    ];

    // Call the AES CBC decryption function with PKCS#7 padding removal
    let plaintext = aes_dec_cbc(&ciphertext, &key, &iv, Some("PKCS7")).expect("Decryption failed");

    // Convert the expected plaintext to Vec<u8> for comparison
    let expected_plaintext_vec: Vec<u8> = expected_plaintext.to_vec();

    // Assert that the produced plaintext matches the expected plaintext
    assert_eq!(
        plaintext, expected_plaintext_vec,
        "Plaintext does not match expected value"
    );
}

#[test]
fn test_aes_enc_cbc_error_invalid_plaintext_length() {
    let plaintext = [0u8; 10]; // Length not a multiple of AES_BLOCK_SIZE
    let key = [0u8; 16];
    let iv = [0u8; 16];

    let result = aes_enc_cbc(&plaintext, &key, &iv, None);

    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(
            e.to_string(),
            "AES ENC CBC Error: Plaintext must be a multiple of AES_BLOCK_SIZE for 'None' padding"
        );
    }
}

#[test]
fn test_aes_dec_cbc_error_invalid_ciphertext_length() {
    let ciphertext = [0u8; 10]; // Length not a multiple of AES_BLOCK_SIZE
    let key = [0u8; 16];
    let iv = [0u8; 16];

    let result = aes_dec_cbc(&ciphertext, &key, &iv, None);

    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(
            e.to_string(),
            "AES DEC CBC Error: Ciphertext must be a multiple of AES_BLOCK_SIZE"
        );
    }
}

#[test]
fn test_aes_enc_cbc_with_80_padding() {
    let plaintext = hex::decode("FFFFFFFFFFFFFFFF").unwrap();
    let key = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let iv = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_ciphertext = hex::decode("8C9D8A1544C87C97ED44C81382B7FBA7").unwrap();

    let iv_array: [u8; 16] = iv.try_into().expect("Invalid IV length");

    let ciphertext =
        aes_enc_cbc(&plaintext, &key, &iv_array, Some("0x80")).expect("Encryption failed");

    assert_eq!(
        ciphertext, expected_ciphertext,
        "Ciphertext does not match expected value with 0x80 padding"
    );
}

#[test]
fn test_aes_dec_cbc_with_80_padding_removal() {
    let ciphertext = hex::decode("8C9D8A1544C87C97ED44C81382B7FBA7").unwrap();
    let key = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let iv = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_plaintext = hex::decode("FFFFFFFFFFFFFFFF").unwrap();

    let iv_array: [u8; 16] = iv.try_into().expect("Invalid IV length");

    let plaintext =
        aes_dec_cbc(&ciphertext, &key, &iv_array, Some("0x80")).expect("Decryption failed");

    // Truncate the plaintext to the original length for comparison
    let truncated_plaintext = &plaintext[..expected_plaintext.len()];

    assert_eq!(
        truncated_plaintext, expected_plaintext,
        "Decrypted plaintext does not match expected value with 0x80 padding removal"
    );
}
