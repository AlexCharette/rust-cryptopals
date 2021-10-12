
pub fn hexstr_to_base64(hex_str: &str) -> String {
    base64::encode(&hexstr_to_bytes(hex_str))
}

pub fn base64_to_hex(b64_str: &str) -> String { 
    let b64_bytes = base64::decode(b64_str).expect("Failed to decode base64 string");
    hex::encode(&b64_bytes)
}

pub fn hexstr_to_bytes(hex_str: &str) -> Vec<u8> {
    let mut hex_bytes = hex_str.as_bytes().iter().filter_map(|b| {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }).fuse();
    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes
}

pub fn byte_to_nibble(byte: u8) -> u8 {
    let h = byte & 0xF;
    match h < 0xA {
        true => b'0' + h,
        false => b'a' + (h - 0xA)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_b64_to_hex() {
        let b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(base64_to_hex(b64_str), expected)
    }


    #[test] // Cryptopals 1:1
    fn converts_hex_to_b64() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bytes = hexstr_to_bytes(hex_str);
        assert_eq!(&base64::encode(&bytes), expected);
    } 
}