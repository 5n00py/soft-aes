use super::super::aes_ecb::*;
use hex::decode as hex_decode;

#[test]
fn test_aes_enc_ecb_no_padding() {
    // Define the plaintext, key, and expected ciphertext as byte arrays
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let key: [u8; 16] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];
    let expected_ciphertext: [u8; 16] = [
        0xDA, 0x4A, 0x08, 0xFF, 0xFA, 0x92, 0xB3, 0x19, 0x12, 0x3A, 0x07, 0x13, 0x2A, 0x20, 0x65,
        0xC6,
    ];

    // Call the encryption function
    let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

    // Assert that the produced ciphertext matches the expected ciphertext
    assert_eq!(
        ciphertext.as_slice(),
        expected_ciphertext.as_slice(),
        "Ciphertext does not match expected value"
    );
}

#[test]
fn test_aes_dec_ecb_no_padding() {
    // Define the expected plaintext, key, and ciphertext as byte arrays
    let expected_plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let key: [u8; 16] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];
    let ciphertext: [u8; 16] = [
        0xDA, 0x4A, 0x08, 0xFF, 0xFA, 0x92, 0xB3, 0x19, 0x12, 0x3A, 0x07, 0x13, 0x2A, 0x20, 0x65,
        0xC6,
    ];

    // Call the decryption function
    let decrypted_plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

    // Assert that the decrypted plaintext matches the expected plaintext
    assert_eq!(
        decrypted_plaintext.as_slice(),
        expected_plaintext.as_slice(),
        "Decrypted plaintext does not match expected value"
    );
}

#[test]
fn test_aes_enc_ecb_with_pkcs7_padding() {
    // Define the plaintext and key as byte arrays
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let key: [u8; 16] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];

    // Define the expected ciphertext as a byte array
    let expected_ciphertext: [u8; 32] = [
        0xDA, 0x4A, 0x08, 0xFF, 0xFA, 0x92, 0xB3, 0x19, 0x12, 0x3A, 0x07, 0x13, 0x2A, 0x20, 0x65,
        0xC6, 0x84, 0x8C, 0xB0, 0x14, 0x0D, 0xE6, 0x94, 0xB9, 0x7C, 0xBC, 0x6B, 0xC9, 0xFF, 0xF7,
        0xAB, 0x59,
    ];

    // Call the encryption function with PKCS7 padding
    let ciphertext = aes_enc_ecb(&plaintext, &key, Some("PKCS7")).expect("Encryption failed");

    // Assert that the produced ciphertext matches the expected ciphertext
    assert_eq!(
        ciphertext, expected_ciphertext,
        "Ciphertext does not match expected value"
    );
}

#[test]
fn test_aes_dec_ecb_with_pkcs7_padding_removal() {
    // Define the ciphertext and key as byte arrays
    let ciphertext: [u8; 32] = [
        0xDA, 0x4A, 0x08, 0xFF, 0xFA, 0x92, 0xB3, 0x19, 0x12, 0x3A, 0x07, 0x13, 0x2A, 0x20, 0x65,
        0xC6, 0x84, 0x8C, 0xB0, 0x14, 0x0D, 0xE6, 0x94, 0xB9, 0x7C, 0xBC, 0x6B, 0xC9, 0xFF, 0xF7,
        0xAB, 0x59,
    ];
    let key: [u8; 16] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];

    // Define the expected plaintext as a byte array
    let expected_plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    // Call the decryption function with PKCS7 padding removal
    let plaintext = aes_dec_ecb(&ciphertext, &key, Some("PKCS7")).expect("Decryption failed");

    // Assert that the decrypted plaintext matches the expected plaintext
    assert_eq!(
        plaintext, expected_plaintext,
        "Decrypted plaintext does not match expected value"
    );
}

#[test]
fn test_aes_enc_ecb_with_80_padding() {
    let plaintext = hex_decode("FFFFFFFFFFFFFFFF").unwrap();
    let key = hex_decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_ciphertext = hex_decode("F8CA20FB687D85A6666460654527E3C3").unwrap();

    let ciphertext = aes_enc_ecb(&plaintext, &key, Some("0x80")).expect("Encryption failed");

    assert_eq!(
        ciphertext, expected_ciphertext,
        "Ciphertext does not match expected value with 0x80 padding"
    );
}

#[test]
fn test_aes_dec_ecb_with_80_padding_removal() {
    let ciphertext = hex_decode("F8CA20FB687D85A6666460654527E3C3").unwrap();
    let key = hex_decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_plaintext = hex_decode("FFFFFFFFFFFFFFFF").unwrap(); // Original plaintext before padding

    let plaintext = aes_dec_ecb(&ciphertext, &key, Some("0x80")).expect("Decryption failed");

    // Truncate the plaintext to the original length for comparison
    let truncated_plaintext = &plaintext[..expected_plaintext.len()];

    assert_eq!(
        truncated_plaintext, expected_plaintext,
        "Decrypted plaintext does not match expected value with 0x80 padding removal"
    );
}
