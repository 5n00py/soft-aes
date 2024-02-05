use crate::padding::*;

#[test]
fn test_pad_80() {
    let mut data = vec![0x01, 0x02, 0x03];
    let block_size = 8;
    pad_80(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_pad_80_for_empty_vector() {
    let mut data = vec![];
    let block_size = 4;
    pad_80(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x80, 0x00, 0x00, 0x00]);
}

#[test]
fn test_pad_80_for_exact_multiple_length() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04];
    let block_size = 4;
    pad_80(&mut data, block_size).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x80, 0x00, 0x00, 0x00]);
}

#[test]
fn test_pad_80_invalid_block_size_zero() {
    let mut data = vec![0x01, 0x02, 0x03];
    let block_size = 0;
    assert!(pad_80(&mut data, block_size).is_err());
}

#[test]
fn test_unpad_80_valid_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x80, 0x00, 0x00, 0x00];
    unpad_80(&mut data).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_unpad_80_no_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04];
    let result = unpad_80(&mut data);
    assert!(result.is_err());
}

#[test]
fn test_unpad_80_inconsistent_padding() {
    let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x80, 0x01, 0x00, 0x00];
    let result = unpad_80(&mut data);
    assert!(result.is_err());
}

#[test]
fn test_unpad_80_empty_data() {
    let mut data = Vec::new();
    let result = unpad_80(&mut data);
    assert!(result.is_err());
}
