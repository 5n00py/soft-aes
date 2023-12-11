//! Test Suite for AES ECB Implementation Against NIST AESAVS
//!
//! This module contains tests for validating the AES ECB (Electronic Codebook)
//! mode implementation against the Known Answer Tests (KAT) provided by The
//! Advanced Encryption Standard Algorithm Validation Suite (AESAVS) released
//! on November 15, 2002.
//!
//! The tests are designed to ensure that the AES ECB implementation conforms to
//! the standards and recommendations set forth by the National Institute of
//! Standards and Technology (NIST), particularly as detailed by Lawrence E.
//! Bassham III from the NIST Information Technology Laboratory, Computer
//! Security Division.
//!
//! The AESAVS document serves as a guideline and basis for these tests and can
//! be found at:
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
//!
//! # Tests Overview
//!
//! - The tests cover various aspects of AES ECB mode, including encryption and
//!   decryption processes, for different key sizes (128, 192, and 256 bits).
//! - Test vectors used in these tests include plaintexts, ciphertexts, and
//!   keys as specified in the AESAVS documentation.
//! - Both encryption and decryption functionalities are tested against fixed
//!   plaintexts and varying keys, as well as varying plaintexts with fixed keys,
//!   to ensure comprehensive coverage and conformance with the AES standard.
//!
//! The test cases in this module are critical for verifying the correctness and
//! reliability of the AES ECB implementation, especially for applications
//! requiring cryptographic standards compliance and robust data security.

use crate::aes::{aes_dec_ecb, aes_enc_ecb};

use hex;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[test]
fn test_aes_enc_ecb_vartxt_kat_aes_128() {
    let key = [0u8; 16]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_1_vartxt_kat_keysize_128_pt_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_1_vartxt_kat_keysize_128_ct_values.txt");

    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (plaintext_str, expected_ciphertext_str) in plaintext_lines.zip(ciphertext_lines) {
        let plaintext_hex = plaintext_str.expect("Error reading plaintext line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let plaintext = hex::decode(plaintext_hex).expect("Failed to decode plaintext hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_enc_ecb_vartxt_kat_aes_192() {
    let key = [0u8; 24]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_2_vartxt_kat_keysize_192_pt_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_2_vartxt_kat_keysize_192_ct_values.txt");

    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (plaintext_str, expected_ciphertext_str) in plaintext_lines.zip(ciphertext_lines) {
        let plaintext_hex = plaintext_str.expect("Error reading plaintext line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let plaintext = hex::decode(plaintext_hex).expect("Failed to decode plaintext hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_enc_ecb_vartxt_kat_aes_256() {
    let key = [0u8; 32]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_3_vartxt_kat_keysize_256_pt_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_3_vartxt_kat_keysize_256_ct_values.txt");

    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (plaintext_str, expected_ciphertext_str) in plaintext_lines.zip(ciphertext_lines) {
        let plaintext_hex = plaintext_str.expect("Error reading plaintext line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let plaintext = hex::decode(plaintext_hex).expect("Failed to decode plaintext hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_vartxt_kat_aes_128() {
    let key = [0u8; 16]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_1_vartxt_kat_keysize_128_ct_values.txt");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_1_vartxt_kat_keysize_128_pt_values.txt");

    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");
    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");

    for (ciphertext_str, expected_plaintext_str) in ciphertext_lines.zip(plaintext_lines) {
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");
        let expected_plaintext_hex = expected_plaintext_str.expect("Error reading plaintext line");

        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");
        let expected_plaintext =
            hex::decode(expected_plaintext_hex).expect("Failed to decode plaintext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_vartxt_kat_aes_192() {
    let key = [0u8; 24]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_2_vartxt_kat_keysize_192_ct_values.txt");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_2_vartxt_kat_keysize_192_pt_values.txt");

    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");
    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");

    for (ciphertext_str, expected_plaintext_str) in ciphertext_lines.zip(plaintext_lines) {
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");
        let expected_plaintext_hex = expected_plaintext_str.expect("Error reading plaintext line");

        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");
        let expected_plaintext =
            hex::decode(expected_plaintext_hex).expect("Failed to decode plaintext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_vartxt_kat_aes_256() {
    let key = [0u8; 32]; // All zeros key

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_3_vartxt_kat_keysize_256_ct_values.txt");
    let plaintext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_d_3_vartxt_kat_keysize_256_pt_values.txt");

    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");
    let plaintext_lines = read_lines(plaintext_file).expect("Failed to read plaintext file");

    for (ciphertext_str, expected_plaintext_str) in ciphertext_lines.zip(plaintext_lines) {
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");
        let expected_plaintext_hex = expected_plaintext_str.expect("Error reading plaintext line");

        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");
        let expected_plaintext =
            hex::decode(expected_plaintext_hex).expect("Failed to decode plaintext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

#[test]
fn test_aes_enc_ecb_varkey_kat_aes_128() {
    let plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_1_varkey_kat_keysize_128_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_1_varkey_kat_keysize_128_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, expected_ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_enc_ecb_varkey_kat_aes_192() {
    let plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_2_varkey_kat_keysize_192_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_2_varkey_kat_keysize_192_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, expected_ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_enc_ecb_varkey_kat_aes_256() {
    let plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_3_varkey_kat_keysize_256_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_3_varkey_kat_keysize_256_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, expected_ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let expected_ciphertext_hex =
            expected_ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let expected_ciphertext =
            hex::decode(expected_ciphertext_hex).expect("Failed to decode ciphertext hex");

        let ciphertext = aes_enc_ecb(&plaintext, &key, None).expect("Encryption failed");

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Ciphertext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_varkey_kat_aes_128() {
    let expected_plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_1_varkey_kat_keysize_128_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_1_varkey_kat_keysize_128_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_varkey_kat_aes_192() {
    let expected_plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_2_varkey_kat_keysize_192_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_2_varkey_kat_keysize_192_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

#[test]
fn test_aes_dec_ecb_varkey_kat_aes_256() {
    let expected_plaintext = [0u8; 16]; // All zeros plaintext

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_3_varkey_kat_keysize_256_key_values.txt");
    let ciphertext_file = Path::new(manifest_dir)
        .join("src/aes/tests/nist/aesavs_appendix_e_3_varkey_kat_keysize_256_ct_values.txt");

    let key_lines = read_lines(key_file).expect("Failed to read key file");
    let ciphertext_lines = read_lines(ciphertext_file).expect("Failed to read ciphertext file");

    for (key_str, ciphertext_str) in key_lines.zip(ciphertext_lines) {
        let key_hex = key_str.expect("Error reading key line");
        let ciphertext_hex = ciphertext_str.expect("Error reading ciphertext line");

        let key = hex::decode(key_hex).expect("Failed to decode key hex");
        let ciphertext = hex::decode(ciphertext_hex).expect("Failed to decode ciphertext hex");

        let plaintext = aes_dec_ecb(&ciphertext, &key, None).expect("Decryption failed");

        assert_eq!(
            plaintext, expected_plaintext,
            "Plaintext does not match expected value"
        );
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
