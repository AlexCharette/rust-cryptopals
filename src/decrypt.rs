use std::convert::TryFrom;
use std::str::from_utf8;
use base64::DecodeError;
use crypto::{
    aes::{ecb_decryptor, KeySize}, 
    blockmodes, 
    symmetriccipher::SymmetricCipherError, 
    buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer}
};
use log::info;
use openssl::symm::{Cipher, decrypt};

use crate::pad_pkcs7;

use super::analyse::*;
use super::convert::*;
use super::encrypt::*;

pub struct DecryptResult<T> {
    pub output: T,
    pub key: Option<T>,
}

pub fn dec_aes128_cbc(bytes: &mut [u8], key: &[u8], block_size: usize) -> String {
    info!("Input {:?}\nInput Length: {:?}", bytes, bytes.len());
    assert_eq!(key.len(), block_size);

    let mut prev_block = vec![0u8; block_size];
    let mut plain_blocks = Vec::<Vec<u8>>::new();
    pad_pkcs7(&mut bytes.to_vec(), block_size);
    // TODO Is there some way I can make this a vector of slices and have it be functional?
    let mut blocks: Vec<Vec<u8>> = bytes.chunks_mut(block_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    blocks.iter_mut().for_each(|block| {
        // Decrypt
        match dec_aes128_ecb_to_bytes(&block, key, false) {
            Ok(res) => {
                let decrypted_data = res.output;
                assert_eq!(decrypted_data.len(), prev_block.len());
                let plaintext = fixed_xor(&decrypted_data, &prev_block);
                prev_block = block.clone();    
                plain_blocks.push(plaintext);
            },
            // TODO find a way to use this error
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    });
    let plain_bytes: Vec<u8> = plain_blocks.into_iter().flatten().collect();
    info!("plain bytes: {:?}", plain_bytes);
    let plaintext = String::from_utf8_lossy(&plain_bytes);
    plaintext.to_string()
}

pub fn dec_aes128_ecb_to_bytes(bytes: &[u8], key: &[u8], pad: bool) -> Result<DecryptResult<Vec<u8>>, SymmetricCipherError> {
    info!("Input {:?}\nInput Length: {:?}", bytes, bytes.len());

    let mut decryptor = if pad {
        ecb_decryptor(
            KeySize::KeySize128, 
            key, 
            blockmodes::PkcsPadding,
        )
    } else {
        ecb_decryptor(
            KeySize::KeySize128, 
            key, 
            blockmodes::NoPadding,
        )
    };
    let mut final_result = Vec::<u8>::new();
    let mut read_buff = RefReadBuffer::new(&bytes);
    let mut out_buff = [0u8; 4096];
    let mut write_buff = RefWriteBuffer::new(&mut out_buff);
    loop {
        let result = decryptor.decrypt(&mut read_buff, &mut write_buff, true)?;

        final_result.extend(write_buff.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    
    info!("Ouput {:?}\nLength: {:?}", final_result, final_result.len());

    Ok(DecryptResult::<Vec<u8>> {
        output: final_result.to_vec(),
        key: None,
    })
}

pub fn dec_aes128_ecb_to_string(bytes: &[u8], key: &[u8], pad: bool) -> Result<DecryptResult<String>, SymmetricCipherError> {
    info!("Input {:?}\nInput Length: {:?}", bytes, bytes.len());

    let mut decryptor = if pad {
        ecb_decryptor(
            KeySize::KeySize128, 
            key, 
            blockmodes::PkcsPadding,
        )
    } else {
        ecb_decryptor(
            KeySize::KeySize128, 
            key, 
            blockmodes::NoPadding,
        )
    };
    let mut final_result = Vec::<u8>::new();
    let mut read_buff = RefReadBuffer::new(&bytes);
    let mut out_buff = [0u8; 4096];
    let mut write_buff = RefWriteBuffer::new(&mut out_buff);
    loop {
        let result = decryptor.decrypt(&mut read_buff, &mut write_buff, true)?;

        final_result.extend(write_buff.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    
    let plaintext = String::from_utf8_lossy(&final_result);
    info!("Final Result {:?} - Length: {:?}", plaintext, plaintext.len());

    Ok(DecryptResult::<String> {
        output: plaintext.to_string(),
        key: None,
    })
}

pub fn dec_aes128_ecb_b64(b64_str: &str, key: &str, iv: &[u8]) -> Result<DecryptResult<String>, DecodeError> {
    info!("Input {:?}\nInput Length: {:?}", b64_str, b64_str.len());
    let bytes: Vec<u8>;
    match base64::decode(b64_str) {
        Ok(v) => {
            bytes = v;
        },
        Err(err) => {
            return Err(err);
        },
    };
    let mut decryptor = ecb_decryptor(
        KeySize::KeySize128, 
        key.as_bytes(), 
        blockmodes::PkcsPadding,
    );
    let mut input = RefReadBuffer::new(&bytes);
    let mut out_buff = &mut [0u8; 16];
    let mut output = RefWriteBuffer::new(out_buff);
    decryptor.decrypt(&mut input, &mut output, false).expect("Failed to decrypt data");

    let plaintext = from_utf8(out_buff).expect("Failed to convert bytes to valid utf-8");

    Ok(DecryptResult::<String> {
        output: String::from(plaintext),
        key: None,
    })
}

pub fn dec_repeat_xor(b64_str: &str) -> Result<DecryptResult<String>, DecodeError> {
    info!("Input {:?}\nInput Length: {:?}", b64_str, b64_str.len());
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

    Ok(DecryptResult::<String> {
        output: String::from(plaintext), 
        key: Some(String::from(key)),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::path::PathBuf;
    use simple_logger::SimpleLogger;
    use super::*;

    fn init() {
        SimpleLogger::new().init().unwrap();
    }

    #[test] // Cryptopals 2:2
    fn decrypts_xor_cbc() {
        // init();
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
            result = dec_aes128_cbc(&mut ciphertext.as_bytes_mut(), key, 16);
        }
        
        // CURRENTLY this seems to just be printing the numerical code for each byte
        info!("{}", result);
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

        // log!("{}\n{}", result.plaintext, result.key);
        assert_eq!(result.key.unwrap(), expected);
    }
}