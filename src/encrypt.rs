use std::error::Error;
use std::str::from_utf8;
use base64::DecodeError;
use hex::ToHex;
use openssl::{error::ErrorStack, symm::{Cipher, encrypt}};
use super::pad_pkcs7;

pub fn enc_xor_cbc(bytes: &mut [u8], key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    const BLOCK_SIZE: usize = 16;
    assert_eq!(key.len(), BLOCK_SIZE);

    let mut prev_ciphertext = vec![0u8; BLOCK_SIZE];
    let mut cipher_blocks = Vec::<Vec<u8>>::new();
    // TODO Is there some way I can make this a vector of slices and have it be functional?
    let mut blocks: Vec<Vec<u8>> = bytes.chunks_mut(BLOCK_SIZE).map(|chunk| chunk.to_vec()).collect();
    blocks.iter_mut().for_each(|block| {
        println!("prev: {:?}", prev_ciphertext);
        if block.len() < BLOCK_SIZE {
            pad_pkcs7(block, BLOCK_SIZE);
            assert!(block.len() == BLOCK_SIZE);
        }
        let fake_iv: Vec<u8> = vec![];
        let ciphertext = fixed_xor(block, &prev_ciphertext);
        let encrypted_bytes = enc_aes128_ecb(&ciphertext, &key, &fake_iv);
        match encrypted_bytes {
            Ok(bytes) => {
                prev_ciphertext = bytes.clone();
                cipher_blocks.push(bytes);
            },
            Err(err) => {},
        }
    });
    let encrypted_bytes: Vec<u8> = cipher_blocks.into_iter().flatten().collect();
    println!("cipher bytes: {:?}", encrypted_bytes);
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn enc_aes128_ecb(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    encrypt(
        cipher, 
        &key,
        Some(iv),
        bytes,
    )
}

pub fn enc_aes128_ecb_b64(b64_str: &str, key: &str, iv: &[u8]) -> Result<String, DecodeError> {
    let bytes: Vec<u8>;
    match base64::decode(b64_str) {
        Ok(v) => {
            bytes = v;
        },
        Err(err) => {
            return Err(err);
        },
    };
    let cipher = Cipher::aes_128_ecb();
    let ciphertext = encrypt(
        cipher, 
        &key.as_bytes(),
        Some(iv),
        &bytes,
    ).unwrap();
    let ciphertext = from_utf8(&ciphertext).expect("Failed to convert bytes to valid utf-8");

    Ok(String::from(ciphertext))
}

pub fn enc_repeat_xor(bytes: &[u8], key: &[u8]) -> Result<String, Box<dyn Error>> {
    let key_length = key.len();
    let encrypted_bytes: Vec<u8> = bytes.iter().enumerate().map(|(index, &b)| {
        b ^ key[index % key_length]
    }).collect();
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn enc_repeat_xor_str(str: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let text_bytes = str.as_bytes();
    let key_bytes = key.as_bytes();
    let key_length = key.len();
    let encrypted_bytes: Vec<u8> = text_bytes.iter().enumerate().map(|(index, &b)| {
        b ^ key_bytes[index % key_length]
    }).collect();
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn fixed_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.len(), key.len());

    bytes
        .iter()
        .zip(key.iter())
        .map(|(&hex, &key)| hex ^ key)
        .collect()
}

pub fn enc_fixed_xor_str(hex_str: &str, key: &str) -> Result<String, Box<dyn Error>> {
    assert_eq!(hex_str.len(), key.len());

    let hex_bytes = hex::decode(hex_str).expect("Failed to decode hex string");
    let key_bytes = hex::decode(key).expect("Failed to decode key");
    let encrypted_bytes: Vec<u8> =  hex_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&hex, &key)| hex ^ key)
        .collect();
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn enc_single_char_xor(bytes: &[u8], key: u32) -> Result<String, Box<dyn Error>> {
    let chars: Vec<char> = bytes.iter().map(|&b| {
        let xor_char = (b as u32) ^ key;
        match std::char::from_u32(xor_char) {
            Some(valid_char) => valid_char,
            None => '0',
        }
    }).collect();
    Ok(chars.into_iter().collect())
}

pub fn enc_single_char_xor_on_hex(hex_str: &str, key: u32) -> Result<String, Box<dyn Error>> {
    let bytes = hex::decode(hex_str).expect("Failed to decode hex string");
    let chars: Vec<char> = bytes.iter().map(|&b| {
        let xor_char = (b as u32) ^ key;
        match std::char::from_u32(xor_char) {
            Some(valid_char) => valid_char,
            None => '0',
        }
    }).collect();
    Ok(chars.into_iter().collect())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test] // Cryptopals 1:5
    fn encrypts_repeat_xor() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(&enc_repeat_xor_str(plaintext, key).ok().unwrap(), expected);
    }

    #[test] // Cryptopals 1:2
    fn encrypts_fixed_xor() {
        let input = "1c0111001f010100061a024b53535009181c";
        let key = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";
        assert_eq!(&enc_fixed_xor_str(input, key).ok().unwrap(), expected);
    } 
}
