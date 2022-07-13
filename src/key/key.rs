use crypto::{digest::Digest, ripemd160::Ripemd160, sha2::Sha256};

use crate::utils::ToByteArray;

pub trait Key {
    fn from_str(s: &str) -> Result<Vec<u8>, hex::FromHexError>;
    fn as_hex_string(&mut self) -> String;
    fn append_checksum(&mut self) -> ();
    fn hash160(self) -> Vec<u8>;
}

impl Key for Vec<u8> {
    fn from_str(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
        Ok(s.to_string().to_byte_array()?)
    }

    fn as_hex_string(&mut self) -> String {
        hex::encode(self)
    }

    fn append_checksum(&mut self) {
        let mut buff = [0x00; 32];
        let mut hasher = Sha256::new();

        hasher.input(&self);
        hasher.result(&mut buff);
        hasher.reset();

        hasher.input(&buff);
        hasher.result(&mut buff);

        self.append(&mut buff[0..4].to_vec());
    }

    fn hash160(self) -> Vec<u8> {
        let mut buff = [0x00; 32];

        let mut hasher = Sha256::new();
        hasher.input(&self);
        hasher.result(&mut buff);

        let mut hasher = Ripemd160::new();
        hasher.input(&buff);
        hasher.result(&mut buff);

        buff[0..20].to_vec()
    }
}

#[cfg(test)]
mod keys_tests {
    use super::*;
    use crate::key::{PRIVATE_KEY, UNCOMPRESSED_PUBLIC_KEY, COMPRESSED_PUBLIC_KEY};

    #[test]
    fn test_constructor() {
        assert_eq!(Vec::from_str("0").unwrap(), vec![0x00]);
        assert_eq!(Vec::from_str("00").unwrap(), vec![0x00]);
        assert_eq!(
            Vec::from_str("012345").unwrap(),
            vec![0x01, 0x23, 0x45]
        )
    }

    #[test]
    fn should_throw_error_if_invalid_character() {
        assert_eq!(
            Vec::from_str("0123456789abcdefg"),
            Err(hex::FromHexError::InvalidHexCharacter { c: 'g', index: 17 })
        )
    }

    #[test]
    fn should_return_bytes_encoded_as_hex_string() {
        let expected = PRIVATE_KEY.to_string();
        let actual = Vec::from_str(PRIVATE_KEY).unwrap().as_hex_string();

        assert_eq!(expected, actual);
    }

    #[test]
    fn should_append_exactly_four_bytes() {
        let mut key = Vec::from_str("01234").unwrap();
        let length = key.len();

        key.append_checksum();

        assert_eq!(length + 4, key.len())
    }

    #[test]
    fn should_append_expected_bytes_as_checksum() {
        let mut key = Vec::from_str("344b160161c7b41a82fe8d6aebb55eaab753cb60").unwrap();
        key.append_checksum();
        let expected = "344b160161c7b41a82fe8d6aebb55eaab753cb60dabd0ca2";

        assert_eq!(key.as_hex_string(), expected);
    }

    fn get_hash160_length(input: &str) -> usize {
        Vec::from_str(input).unwrap().hash160().len()
    }

    #[test]
    fn hash160_should_be_20_bytes_long() {
        let expected = 20;

        let actual = get_hash160_length(UNCOMPRESSED_PUBLIC_KEY);
        assert_eq!(actual, expected);

        let actual = get_hash160_length(COMPRESSED_PUBLIC_KEY);
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash160_from_compressed_pubkey() {
        assert_eq!(
            Vec::from_str(COMPRESSED_PUBLIC_KEY).unwrap().hash160(),
            hex::decode("bbc1e42a39d05a4cc61752d6963b7f69d09bb27b").unwrap(),
        )
    }

    #[test]
    fn hash160_from_uncompressed_pubkey() {
        assert_eq!(
            Vec::from_str(UNCOMPRESSED_PUBLIC_KEY).unwrap().hash160(),
            hex::decode("211b74ca4686f81efda5641767fc84ef16dafe0b").unwrap(),
        )
    }
}
