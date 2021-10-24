use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use log::info;
use phf::phf_map;
use super::encrypt::*;

const CHAR_MISS_PENALTY: f32 = 50.0;
const KEY_RANGE: u32 = 255;
static CHAR_FREQS_ENG: phf::Map<char, f32> = phf_map! {
    'a' => 8.167, 'b' => 1.492, 'c' => 2.782, 'd' => 4.253, 'e' => 12.702,
    'f' => 2.228, 'g' => 2.015, 'h' => 6.094, 'i' => 6.966, 'j' => 0.153,
    'k' => 0.772, 'l' => 4.025, 'm' => 2.406, 'n' => 6.749, 'o' => 7.507,
    'p' => 1.929, 'q' => 0.095, 'r' => 5.987, 's' => 6.327, 't' => 9.056,
    'u' => 2.758, 'v' => 0.978, 'w' => 2.360, 'x' => 0.150, 'y' => 1.974, 
    'z' => 0.074, ' ' => 17.166, '\'' => 0.244, ',' => 0.738, '.' => 1.512,
};

pub struct AnalysisResult {
    pub plaintext: String,
    pub score: f32,
    pub key: u32,
}

pub fn detect_aes_ecb_in_file(file_path: &PathBuf, keysize: usize) -> String {
    let file = File::open(&file_path).expect("Failed to find file");
    let file = BufReader::new(file);

    let mut highest_duplicate_count = 0;
    let mut candidate = String::new();
    let mut cipher_bytes = Vec::<u8>::new();
    let hash_state = RandomState::new();
    let mut matching_chunks = HashMap::<u64, Vec<Vec<u8>>>::new();

    // Each line is presumed to be a distinct ciphertext
    file.lines().for_each(|line| {
        match line {
            Ok(line) => {
                let mut duplicate_count = 0;
                cipher_bytes = hex::decode(&line).expect("Failed to decode hex string");
                cipher_bytes
                    .chunks(keysize / 8)
                    .for_each(|chunk| {
                        let mut hasher = hash_state.build_hasher();
                        hasher.write(chunk);
                        let hash = hasher.finish();
                        if let Some(chunks) = matching_chunks.get_mut(&hash) {
                            chunks.push(chunk.to_vec());
                            duplicate_count += 1;
                        } else {
                            matching_chunks.insert(hash, vec![vec![0u8]]);
                        }
                        // Each identical chunk of X bytes should produce the same result when XOR'd
                        // Similar chunks should have a short hamming distance
                        // Hash each chunk
                    });
                if duplicate_count > highest_duplicate_count {
                    highest_duplicate_count = duplicate_count;
                    candidate = line;
                }
            },
            Err(_) => {},
        }
        matching_chunks.clear();
    }); 
    String::from(candidate)
}

pub fn find_message_in_file_1cx(file_path: &PathBuf) -> String {
    let file = File::open(&file_path).expect("Failed to find file");
    let file = BufReader::new(file);
    // Get the best score for each line
    let mut lowest_score: f32 = f32::MAX;
    let mut current_best = String::new();

    file.lines().for_each(|line| {
        match line {
            Ok(line) => {
                let result = most_likely_eng_1cx_hex(&line);

                if result.score < lowest_score {
                    lowest_score = result.score;
                    current_best = result.plaintext;
                }
            },
            Err(_) => {},
        }
    }); 
    current_best
}

pub fn most_likely_eng_1cx(bytes: &[u8]) -> AnalysisResult {
    let mut lowest_score: f32 = f32::MAX;
    let mut current_best = String::new();
    let mut key = 0;
    for i in 0..=KEY_RANGE {
        let plaintext = enc_single_char_xor(bytes, i);
        if let Ok(result) = plaintext {
            let score = get_char_freq_eng_score(&result.to_lowercase());
            info!("Result: {}", result);
            if score < lowest_score {
                lowest_score = score;
                current_best = result;
                key = i;
            }
        }
    }
    AnalysisResult {
        plaintext: current_best, 
        score: lowest_score, 
        key,
    }
}

pub fn most_likely_eng_1cx_hex(hex_str: &str) -> AnalysisResult {
    let mut lowest_score: f32 = f32::MAX;
    let mut current_best = String::new();
    let mut key = 0;
    for i in 0..=KEY_RANGE {
        let plaintext = enc_single_char_xor_on_hex(hex_str, i);
        if let Ok(result) = plaintext {
            let score = get_char_freq_eng_score(&result.to_lowercase());

            if score < lowest_score {
                lowest_score = score;
                current_best = result;
                key = i;
            }
        }
    }
    AnalysisResult {
        plaintext: current_best, 
        score: lowest_score, 
        key,
    }
}

pub fn get_char_freq_eng_score(str: &str) -> f32 {
    let num_chars = str.len();
    let chars: Vec<char> = str.chars().collect();
    let mut char_counts = HashMap::<char, u32>::new();
    let mut freq_diff = 0f32;
    chars.iter().for_each(|&f| {
        let count = char_counts.entry(f).or_insert(0u32);
        *count += 1;
    });
    char_counts.iter().for_each(|(&key, &val)| {
        if !CHAR_FREQS_ENG.contains_key(&key) {
            freq_diff += CHAR_MISS_PENALTY;
            return;
        }
        let rel_freq = ((val as f32) / (num_chars as f32)) * 100.0;
        match CHAR_FREQS_ENG.get(&key) {
            Some(eng_freq) => freq_diff += (eng_freq - rel_freq).abs(),
            None => {},
        }
    });
    freq_diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::info;
    use simple_logger::SimpleLogger;

    fn init() {
        SimpleLogger::new().init().unwrap();
    }

    #[test] // Cryptopals 1:8
    fn detects_aes_ecb_in_file() {
        // init();
        let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push("data/1.8.txt");
        let result = detect_aes_ecb_in_file(&file_path, 128);
        info!("Result: {}", &result);
        // assert_eq!(result.trim().to_lowercase(), "now that the party is jumping");
    }

    #[test] // Cryptopals 1:4
    fn finds_message_in_file() {
        // init();
        let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push("data/1.4.txt");
        let result = find_message_in_file_1cx(&file_path);
        info!("Result: {}", &result);
        assert_eq!(result.trim().to_lowercase(), "now that the party is jumping");
    }

    #[test] // Cryptopals 1:3
    fn returns_most_likely_eng() {
        // init();
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let result = most_likely_eng_1cx_hex(input);
        info!("Result: {}", result.score);
        assert_eq!(result.plaintext.to_lowercase(), "cooking mc's like a pound of bacon");
    } 
}
