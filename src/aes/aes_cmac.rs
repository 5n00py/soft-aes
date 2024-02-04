use super::aes_core::*;
use crate::padding::pad_80;

const CONST_ZERO: [u8; 16] = [0; 16];
const CONST_RB: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87];

/// Generate subkeys for AES-CMAC.
///
/// # Parameters
/// - `key`: The 128-bit AES key.
///
/// # Returns
/// Returns a tuple of two 128-bit subkeys `(K1, K2)`.
pub fn generate_subkey(key: &[u8]) -> Result<([u8; 16], [u8; 16]), Box<dyn std::error::Error>> {
    // Step 1: L := AES-128(K, const_Zero)
    let l = aes_enc_block(&CONST_ZERO, key)?;

    // Step 2: Generate K1
    let mut k1 = left_shift_one_bit(&l);
    if l[0] & 0x80 != 0 {
        // if MSB(L) == 1
        for (k1_byte, rb_byte) in k1.iter_mut().zip(CONST_RB.iter()) {
            *k1_byte ^= rb_byte;
        }
    }

    // Step 3: Generate K2
    let mut k2 = left_shift_one_bit(&k1);
    if k1[0] & 0x80 != 0 {
        // if MSB(K1) == 1
        for (k2_byte, rb_byte) in k2.iter_mut().zip(CONST_RB.iter()) {
            *k2_byte ^= rb_byte;
        }
    }

    Ok((k1, k2))
}

/// Perform a left bitwise shift by one bit on a 16-byte array.
fn left_shift_one_bit(input: &[u8]) -> [u8; 16] {
    let mut output = [0u8; 16];
    let mut overflow = 0;

    for &byte in input.iter().rev() {
        output.rotate_right(1);
        output[0] = byte << 1 | overflow;
        overflow = (byte >> 7) & 1;
    }

    output
}
