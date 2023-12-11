use crate::padding::*;

#[test]
fn test_pkcs7_pad() {
    let mut data = vec![0x01, 0x02, 0x03];
    let block_size = 8;
    pkcs7_pad(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05]);
}

#[test]
fn test_pcks7_pad_for_empty_vector() {
    let mut data = vec![];
    let block_size = 4;
    pkcs7_pad(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x04, 0x04, 0x04, 0x04]);
}

#[test]
fn test_pkcs7_pad_for_exact_multiple_length() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04];
    let block_size = 4;
    pkcs7_pad(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04]);
}

#[test]
fn test_pkcs7_pad_invalid_block_size_zero() {
    let mut data = vec![0x01, 0x02, 0x03];
    let block_size = 0;
    assert!(pkcs7_pad(&mut data, block_size).is_err());
}

#[test]
fn test_pkcs7_pad_block_size_too_large() {
    let mut data = vec![0x01, 0x02, 0x03];
    let block_size = 256;
    assert!(pkcs7_pad(&mut data, block_size).is_err());
}

#[test]
fn test_pkcs7_unpad_valid_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04];
    pkcs7_unpad(&mut data).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_pkcs7_unpad_no_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04];
    let result = pkcs7_unpad(&mut data);
    assert!(result.is_err());
}

#[test]
fn test_pkcs7_unpad_inconsistent_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x04, 0x04];
    let result = pkcs7_unpad(&mut data);
    assert!(result.is_err());
}

#[test]
fn test_pkcs7_unpad_empty_data() {
    let mut data = Vec::new();
    let result = pkcs7_unpad(&mut data);
    assert!(result.is_err());
}

#[test]
fn test_pkcs7_unpad_invalid_padding_size() {
    let mut data = vec![0x01, 0x02, 0x03, 0x09];
    let result = pkcs7_unpad(&mut data);
    assert!(result.is_err());
}
