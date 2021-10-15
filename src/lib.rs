#![allow(warnings, unused_imports)]

extern crate base64;

pub mod analyse;
pub mod convert;
pub mod decrypt;
pub mod encrypt;

// pub fn bytes_to_valid_utf8(bytes: &mut Vec<u8>) -> Vec<u8> {
//     bytes.iter_mut().for_each(|byte| {
//         if byte > 255 {

//         }
//     })
// }

pub fn pad_pkcs7(bytes: &mut Vec<u8>, size: usize) {
    assert!(bytes.len() < size);
    bytes.resize(size, 4u8);
}

pub fn get_hamming_dist(a: &[u8], b: &[u8]) -> i32 {
    let mut xor: Vec<u8> = a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x ^ y).collect();
    let sum = xor
        .iter_mut()
        .fold(0, |sum, b| {
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

    #[test]
    fn encrypts_and_decrypts_aes128_cbc() {
        let mut plaintext = b"Mellow bubmarone is the guy you wanna talk to".to_owned();
        let key = b"YELLOW SUBMARINE";
        let expected = "Mellow bubmarone is the guy you wanna talk to";
        let ciphertext = encrypt::enc_xor_cbc(&mut plaintext[..], key).ok().unwrap();
        println!("Encrypted: {}", &ciphertext);
        let result = decrypt::dec_xor_cbc(&mut convert::hexstr_to_bytes(&ciphertext), key);
        assert_eq!(&format!("{}", &result), &format!("{}", &expected));
    }

    #[test]
    fn encrypts_and_decrypts_aes128_ecb() {
        let key = "YELLOW SUBMARINE";
        let expected = "Mellow bubmarone";
        let b64_str = base64::encode(expected);
        let iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
            \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let ciphertext = encrypt::enc_aes128_ecb_b64(&b64_str, key, &iv).ok().unwrap();
        println!("Encrypted: {}", &ciphertext);
        let key_bytes = b"YELLOW SUBMARINE";
        let result = decrypt::dec_aes128_ecb(&mut convert::hexstr_to_bytes(&ciphertext), key_bytes, &iv)
            .ok()
            .unwrap();
        assert_eq!(&format!("{}", &result.plaintext), &format!("{}", &expected));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] // Cryptopals 2:1
    fn pads_with_pkcs7() {
        let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        pad_pkcs7(&mut block, 20);
        assert_eq!(&block[..], expected);
    }

    #[test]
    fn computes_hamming_dist() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        assert_eq!(get_hamming_dist(&a.as_bytes(), &b.as_bytes()), 37);
    }
}
