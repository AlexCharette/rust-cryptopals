#![allow(warnings, unused_imports)]

extern crate base64;
extern crate crypto;
extern crate log;

use log::{info, warn};
use openssl::rand::rand_bytes;

pub mod analyse;
pub mod convert;
pub mod decrypt;
pub mod encrypt;

pub fn get_rand_bytes_16() -> Vec<u8> {
    let mut buf = [0u8; 16];
    rand_bytes(&mut buf).unwrap();
    buf.to_vec()
}

// TODO review this - need to pad so that the output is a multiple of size
pub fn pad_pkcs7(bytes: &mut Vec<u8>, size: usize) {
    let mut bytes_length = bytes.len();
    info!("Length: {}", bytes_length);
    let mut mult = 1;
    // Get the multiple of size
    while (mult * size < bytes_length) {
        mult += 1;
    }
    info!("New length: {}", (size * mult));
    bytes.resize(size * mult, 4u8);
}

pub fn get_hamming_dist(a: &[u8], b: &[u8]) -> i32 {
    let mut xor: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect();
    let sum = xor.iter_mut().fold(0, |sum, b| {
        let mut curr_bit: usize = 0;
        let mut temp_sum = 0;
        while curr_bit < 8 {
            if *b & 0x01 == 1 {
                temp_sum += 1;
            }
            curr_bit += 1;
            *b = *b >> 1;
        }
        sum + temp_sum
    });
    sum
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use log::info;
    use simple_logger::SimpleLogger;

    fn init() {
        SimpleLogger::new().init().unwrap();
    }

    #[test]
    fn encrypts_and_decrypts_aes128_cbc() {
        // init();
        let mut plaintext = b"Mellow bubmarone is the guy you wanna talk to".to_owned();
        let key = b"YELLOW SUBMARINE";
        let block_size = 16;
        let expected = "Mellow bubmarone is the guy you wanna talk to";
        let iv = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let mut encrypted_data = encrypt::enc_aes128_cbc(&mut plaintext[..], key, &iv, block_size)
            .ok()
            .unwrap();
        info!("Encrypted: {:?}", &encrypted_data);
        let result = decrypt::dec_aes128_cbc(&mut encrypted_data, key, block_size);
        let contains_expected = result.contains(expected);
        assert!(contains_expected);
    }

    #[test]
    fn encrypts_and_decrypts_aes128_ecb() {
        // init();
        let key = "YELLOW SUBMARINE";
        let expected = "Mellow bubmarone";
        let b64_str = base64::encode(expected);
        let iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
            \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let encrypted_data =
            encrypt::enc_aes128_ecb(expected.as_bytes(), key.as_bytes(), &iv, false)
                .ok()
                .unwrap();
        info!("Encrypted: {:?}", encrypted_data);

        let key_bytes = b"YELLOW SUBMARINE";
        let result = decrypt::dec_aes128_ecb_to_string(&encrypted_data, key_bytes, false)
            .ok()
            .unwrap();
        info!("Result: {:?}", &result.output);
        assert_eq!(&format!("{}", &result.output), &format!("{}", &expected));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_logger::SimpleLogger;

    fn init() {
        SimpleLogger::new().init().unwrap();
    }

    #[test]
    fn generates_aes_key() {
        assert_eq!(get_rand_bytes_16().len(), 16);
    }

    #[test] // Cryptopals 2:1
    fn pads_with_pkcs7() {
        // init();
        let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
        let expected = b"YELLOW SUBMARINE";
        pad_pkcs7(&mut block, 16);
        assert_eq!(block.len(), expected.len());
    }

    #[test]
    fn computes_hamming_dist() {
        // init();
        let a = "this is a test";
        let b = "wokka wokka!!!";
        assert_eq!(get_hamming_dist(&a.as_bytes(), &b.as_bytes()), 37);
    }
}
