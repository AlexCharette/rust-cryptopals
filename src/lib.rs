
extern crate base64;

pub mod analyse;
pub mod convert;
pub mod decrypt;
pub mod encrypt;

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
        let mut plaintext = b"Mellow bubmarone".to_owned();
        let key = b"YELLOW SUBMARINE";
        let expected = "Mellow bubmarone";
        let iv: Vec<u8> = vec![];
        let ciphertext = encrypt::enc_aes128_ecb(&mut plaintext[..], key, &iv).ok().unwrap();
        println!("Encrypted: {}", &ciphertext);
        let result = decrypt::dec_aes128_ecb(&mut convert::hexstr_to_bytes(&ciphertext), key, &iv)
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
