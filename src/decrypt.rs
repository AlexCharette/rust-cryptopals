use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use std::str::from_utf8;
use base64::DecodeError;
use openssl::symm::{Cipher, decrypt};

use super::analyse::*;
use super::convert::*;
use super::encrypt::*;

pub struct DecryptResult {
    pub plaintext: String,
    pub key: Option<String>,
}

pub fn dec_xor_cbc_from_file(file_path: &PathBuf, key: &str, iv: &str) -> String {
    // TODO 
    let file_contents = File::open(&file_path).expect("Failed to find file");
    // Convert file to bytes
    let ciphertext = base64_to_hex();
    // Convert key to bytes
    // Convert IV to bytes
    // C

    return String::from("")
}

pub fn dec_xor_cbc(bytes: &mut [u8], key: &[u8]) -> String {
    const BLOCK_SIZE: usize = 16;
    assert_eq!(key.len(), BLOCK_SIZE);

    let mut prev_ciphertext = vec![0u8; BLOCK_SIZE];
    let mut plain_blocks = Vec::<Vec<u8>>::new();
    // TODO Is there some way I can make this a vector of slices and have it be functional?
    let mut blocks: Vec<Vec<u8>> = bytes.chunks_mut(BLOCK_SIZE).map(|chunk| chunk.to_vec()).collect();
    blocks.iter_mut().for_each(|block| {
        println!("prev: {:?}", prev_ciphertext);
        
        let plaintext = fixed_xor(&fixed_xor(&block, key), &prev_ciphertext);
        prev_ciphertext = plaintext.clone();    
        plain_blocks.push(plaintext);
    });
    let plain_bytes: Vec<u8> = plain_blocks.into_iter().flatten().collect();
    println!("cipher bytes: {:?}", plain_bytes);
    String::from("")
}

pub fn dec_aes128_ecb(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<DecryptResult, DecodeError> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(
        cipher, 
        &key,
        Some(iv),
        &bytes,
    ).unwrap();
    let plaintext = from_utf8(&plaintext).expect("Failed to convert bytes to valid utf-8");

    Ok(DecryptResult {
        plaintext: String::from(plaintext),
        key: None,
    })
}

pub fn dec_aes128_ecb_b64(b64_str: &str, key: &str, iv: &[u8]) -> Result<DecryptResult, DecodeError> {
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
    let plaintext = decrypt(
        cipher, 
        &key.as_bytes(),
        Some(iv),
        &bytes,
    ).unwrap();
    let plaintext = from_utf8(&plaintext).expect("Failed to convert bytes to valid utf-8");

    Ok(DecryptResult {
        plaintext: String::from(plaintext),
        key: None,
    })
}

pub fn dec_repeat_xor(b64_str: &str) -> Result<DecryptResult, DecodeError> {
    let bytes: Vec<u8>;
    match base64::decode(b64_str) {
        Ok(v) => {
            bytes = v;
        },
        Err(err) => {
            return Err(err);
        },
    };

    let mut shortest_dist: f32 = 999.0;
    let mut guessed_keysize: usize = 0;

    for keysize in 2..=40 {
        let hamming_dists: Vec<i32> = bytes
            .chunks(keysize * 2)
            .map(|chunk| super::get_hamming_dist(&chunk[0..chunk.len() / 2], &chunk[chunk.len() / 2..])).collect();
        let dist_total = hamming_dists.iter().fold(0, |sum, dist| sum + dist);
        let dist_avg: f32 = (dist_total as f32) / (hamming_dists.len() as f32);
        let norm_dist = dist_avg / (keysize as f32);
        if norm_dist < shortest_dist {
            shortest_dist = norm_dist;
            guessed_keysize = keysize;
        }
    }

    let mut blocks = vec![vec![0u8]; guessed_keysize];

    blocks.iter_mut().enumerate().for_each(|(i, block)| {
        bytes.chunks(guessed_keysize).for_each(|chunk| {
            if i < chunk.len() {
                block.push(chunk[i]);
            }
        });
    });

    let mut keys = Vec::<u8>::new();
    blocks.iter().for_each(|block| {
        let result = most_likely_eng_1cx(&block);
        keys.push(u8::try_from(result.key).expect("Failed to convert key to u8"));
    });

    let key = from_utf8(&keys).expect("Failed to convert bytes to valid utf-8");
    let plaintext_bytes = hexstr_to_bytes(&enc_repeat_xor(&bytes, &keys).ok().unwrap());
    let plaintext = from_utf8(&plaintext_bytes).expect("Failed to convert bytes to valid utf-8");

    Ok(DecryptResult {
        plaintext: String::from(plaintext), 
        key: Some(String::from(key)),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::path::PathBuf;
    use super::*;

    #[test] // Cryptopals 2:2
    fn decrypts_xor_cbc() {
        let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push("data/2.2.txt");
        let file = File::open(&file_path).expect("Failed to find file");
        let file = BufReader::new(file);

        let mut ciphertext = String::new();
        file.lines().for_each(|l| {
            match l {
                Ok(line) => ciphertext.push_str(line.trim()),
                Err(_) => {},
            }
        });
        let key = b"YELLOW SUBMARINE";
        let mut result = String::from("");
        unsafe {
            result = dec_xor_cbc(&mut ciphertext.as_bytes_mut(), key);
        }
        
        println!("{}", result);
    }

    #[test] // Cryptopals 1:7
    fn decrypts_aes128_ecb() {
        let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push("data/1.7.txt");
        let file = File::open(&file_path).expect("Failed to find file");
        let file = BufReader::new(file);

        let mut ciphertext = String::new();
        file.lines().for_each(|l| {
            match l {
                Ok(line) => ciphertext.push_str(line.trim()),
                Err(_) => {},
            }
        });
        
        let key = "YELLOW SUBMARINE";
        let iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
            \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let result = dec_aes128_ecb_b64(&ciphertext, key, &iv);

        assert_eq!(result.is_ok(), true); // TODO not a great test
    }

    #[test] // Cryptopals 1:6
    fn decrypts_repeat_xor() {
        let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push("data/1.6.txt");
        let file = File::open(&file_path).expect("Failed to find file");
        let file = BufReader::new(file);

        let mut ciphertext = String::new();
        file.lines().for_each(|l| {
            match l {
                Ok(line) => ciphertext.push_str(line.trim()),
                Err(_) => {},
            }
        });

        let expected = "Terminator X: Bring the noise";
        let result = dec_repeat_xor(&ciphertext).ok().unwrap();

        // println!("{}\n{}", result.plaintext, result.key);
        assert_eq!(result.key.unwrap(), expected);
    }
}