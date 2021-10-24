use super::{get_rand_bytes_16, pad_pkcs7};
use base64::DecodeError;
use crypto::{
    aes::{ecb_encryptor, KeySize},
    blockmodes,
    buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer},
    symmetriccipher::SymmetricCipherError,
};
use hex::ToHex;
use log::info;
use openssl::{
    error::ErrorStack,
    symm::{encrypt, Cipher},
};
use rand::{thread_rng, Rng};
use std::error::Error;
use std::fmt::Debug;
use std::str::from_utf8;

// pub fn enc_aes128_rand(bytes: &mut [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
//     // TODO Padd with 5-10 bytes before and after

//     let key = get_rand_bytes_16();
//     let iv = get_rand_bytes_16();
//     let use_ecb = thread_rng().gen_bool(1.0 / 2.0);
//     let encrypted_result: Result<Vec<u8>, Box<dyn Error>>;
//     match use_ecb {
//         true => { // use ecb
//             // enc_aes128_ecb(bytes, &key, &iv)
//         },
//         false => { // use cbc
//             enc_aes128_cbc(bytes, &key, &iv, 16)
//         }
//     }
// }

pub fn enc_aes128_cbc(
    bytes: &mut [u8],
    key: &[u8],
    iv: &[u8],
    block_size: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    assert_eq!(key.len(), block_size);

    let mut prev_block = iv.to_vec();
    let mut cipher_blocks = Vec::<Vec<u8>>::new();
    let mut bytes = bytes.to_vec();
    pad_pkcs7(&mut bytes, 16);
    // Split bytes into a vector of block_size'd chunks
    // TODO Is there some way I can make this a vector of slices and have it be functional?
    let mut blocks: Vec<Vec<u8>> = bytes
        .chunks_mut(block_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    blocks.iter_mut().for_each(|block| {
        let fake_iv: Vec<u8> = vec![];
        assert_eq!(block.len(), prev_block.len());

        let xored_bytes = fixed_xor(block, &prev_block);
        let encrypted_bytes = enc_aes128_ecb(&xored_bytes, &key, &fake_iv, false);
        match encrypted_bytes {
            Ok(bytes) => {
                prev_block = bytes.clone();
                cipher_blocks.push(bytes.to_owned());
            }
            // TODO find a way to use this error
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    });
    let encrypted_bytes: Vec<u8> = cipher_blocks.into_iter().flatten().collect();
    info!("Encrypted bytes: {:?}", encrypted_bytes);
    Ok(encrypted_bytes)
}

pub fn enc_aes128_ecb(
    bytes: &[u8],
    key: &[u8],
    iv: &[u8],
    pad: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = if pad {
        ecb_encryptor(KeySize::KeySize128, key, blockmodes::PkcsPadding)
    } else {
        ecb_encryptor(KeySize::KeySize128, key, blockmodes::NoPadding)
    };
    let mut final_result = Vec::<u8>::new();
    let mut read_buff = RefReadBuffer::new(bytes);
    let mut out_buff = [0u8; 4096];
    let mut write_buff = RefWriteBuffer::new(&mut out_buff);
    loop {
        let result = encryptor.encrypt(&mut read_buff, &mut write_buff, true)?;

        final_result.extend(
            write_buff
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(final_result)
}

pub fn enc_aes128_ecb_b64(b64_str: &str, key: &str, iv: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes: Vec<u8>;
    match base64::decode(b64_str) {
        Ok(v) => {
            bytes = v;
        }
        Err(err) => return Err(Box::new(err)),
    };
    let cipher = Cipher::aes_128_ecb();
    match encrypt(cipher, &key.as_bytes(), Some(iv), &bytes) {
        Ok(res) => Ok(res),
        Err(err) => {
            err.errors()
                .into_iter()
                .for_each(|error| eprintln!("{:?}", error));
            Err(Box::new(err.errors()[0].to_owned()))
        }
    }
}

pub fn enc_repeat_xor(bytes: &[u8], key: &[u8]) -> Result<String, Box<dyn Error>> {
    let key_length = key.len();
    let encrypted_bytes: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(index, &b)| b ^ key[index % key_length])
        .collect();
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn enc_repeat_xor_str(str: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let text_bytes = str.as_bytes();
    let key_bytes = key.as_bytes();
    let key_length = key.len();
    let encrypted_bytes: Vec<u8> = text_bytes
        .iter()
        .enumerate()
        .map(|(index, &b)| b ^ key_bytes[index % key_length])
        .collect();
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
    let encrypted_bytes: Vec<u8> = hex_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&hex, &key)| hex ^ key)
        .collect();
    Ok(encrypted_bytes.encode_hex::<String>())
}

pub fn enc_single_char_xor(bytes: &[u8], key: u32) -> Result<String, Box<dyn Error>> {
    let chars: Vec<char> = bytes
        .iter()
        .map(|&b| {
            let xor_char = (b as u32) ^ key;
            match std::char::from_u32(xor_char) {
                Some(valid_char) => valid_char,
                None => '0',
            }
        })
        .collect();
    Ok(chars.into_iter().collect())
}

pub fn enc_single_char_xor_on_hex(hex_str: &str, key: u32) -> Result<String, Box<dyn Error>> {
    let bytes = hex::decode(hex_str).expect("Failed to decode hex string");
    let chars: Vec<char> = bytes
        .iter()
        .map(|&b| {
            let xor_char = (b as u32) ^ key;
            match std::char::from_u32(xor_char) {
                Some(valid_char) => valid_char,
                None => '0',
            }
        })
        .collect();
    Ok(chars.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] // Cryptopals 1:5
    fn encrypts_repeat_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
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
