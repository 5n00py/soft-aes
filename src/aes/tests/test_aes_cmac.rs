use super::super::aes_cmac::*;
use hex::decode as hex_decode;

#[test]
fn test_subkey_generation() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let (k1, k2) = generate_subkey(&key).unwrap();

    assert_eq!(
        k1.to_vec(),
        hex_decode("fbeed618357133667c85e08f7236a8de").unwrap()
    );
    assert_eq!(
        k2.to_vec(),
        hex_decode("f7ddac306ae266ccf90bc11ee46d513b").unwrap()
    );
}

#[test]
fn test_aes_cmac_128_example1() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = b"";
    let mac = aes_cmac(message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("bb1d6929e95937287fa37d129b756746").unwrap()
    );
}

#[test]
fn test_aes_cmac_128_example2() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = hex_decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap()
    );
}

#[test]
fn test_aes_cmac_128_example3() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = hex_decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
    )
    .unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("dfa66747de9ae63030ca32611497c827").unwrap()
    );
}

#[test]
fn test_aes_cmac_128_example4() {
    let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = hex_decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap()
    );
}

#[test]
fn test_aes_cmac_192_example1() {
    let key = hex_decode("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B").unwrap();
    let message = b"";
    let mac = aes_cmac(message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("D17DDF46ADAACDE531CAC483DE7A9367").unwrap()
    );
}

#[test]
fn test_aes_cmac_192_example2() {
    let key = hex_decode("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B").unwrap();
    let message = hex_decode("6BC1BEE22E409F96E93D7E117393172A").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("9E99A7BF31E710900662F65E617C5184").unwrap()
    );
}

#[test]
fn test_aes_cmac_192_example3() {
    let key = hex_decode("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B").unwrap();
    let message = hex_decode("6BC1BEE22E409F96E93D7E117393172AAE2D8A57").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("3D75C194ED96070444A9FA7EC740ECF8").unwrap()
    );
}

#[test]
fn test_aes_cmac_256_example1() {
    let key =
        hex_decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4").unwrap();
    let message = b"";
    let mac = aes_cmac(message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("028962F61B7BF89EFC6B551F4667D983").unwrap()
    );
}

#[test]
fn test_aes_cmac_256_example2() {
    let key =
        hex_decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4").unwrap();
    let message = hex_decode("6BC1BEE22E409F96E93D7E117393172A").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("28A7023F452E8F82BD4BF28D8C37C35C").unwrap()
    );
}

#[test]
fn test_aes_cmac_256_example3() {
    let key =
        hex_decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4").unwrap();
    let message = hex_decode("6BC1BEE22E409F96E93D7E117393172AAE2D8A57").unwrap();
    let mac = aes_cmac(&message, &key).unwrap();

    assert_eq!(
        mac.to_vec(),
        hex_decode("156727DC0878944A023C1FE03BAD6D93").unwrap()
    );
}

#[test]
fn test_subkey_generation_invalid_key_length() {
    let key = hex_decode("2b7e151628aed2a6").unwrap(); // Shorter key (8 bytes)
    let result = generate_subkey(&key);

    match result {
        Err(e) => assert_eq!(
            e.to_string(),
            "AES CORE ERROR: Invalid key length. Expected 16, 24, or 32 bytes, got 8 bytes",
            "Subkey generation should fail with a specific error for a key of incorrect length."
        ),
        Ok(_) => panic!("Subkey generation should fail for a key of incorrect length."),
    }
}

#[test]
fn test_aes_cmac_invalid_key_length() {
    let key = hex_decode("2b7e151628aed2a6").unwrap(); // Shorter key (8 bytes)
    let message = b"Example message";
    let result = aes_cmac(message, &key);
    assert!(
        matches!(result, Err(e) if e.to_string() == "AES CORE ERROR: Invalid key length. Expected 16, 24, or 32 bytes, got 8 bytes"),
        "AES-CMAC computation should fail with a specific error for a key of incorrect length."
    );
}
