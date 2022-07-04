use crypto::{digest::Digest, sha2::Sha256};

use crate::utils::ToByteArray;

/// A struct representing a Secp256k1 key
///
/// A key is just a number.
/// We represent that number as a vector of bytes.
/// Each byte is represented as an 8 bit unsigned integer.
#[derive(Debug, PartialEq)]
pub struct Key {
    /// Unsigned 8 bit integer vector representing the key.
    pub bytes: Vec<u8>,
}

impl Key {
    /// Returns a Result enum with a Key or an Error
    ///
    /// # Arguments
    ///
    /// * `key_as_str` - A string slice that holds the hexadecimal representation of the key
    pub fn from_str(key_as_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = key_as_str.to_string().to_byte_array()?;

        Ok(Key { bytes })
    }

    /// Returns the key encoded as a string of hexadecimal numbers
    pub fn as_hex_string(self) -> String {
        hex::encode(self.bytes)
    }

    /// Computes and append the checksum to `self.bytes`.
    ///
    /// The checksum is SHA256(SHA256(self.bytes)).
    pub fn append_checksum(&mut self) {
        let mut buff = [0x00; 32];
        let mut hasher = Sha256::new();

        hasher.input(&self.bytes);
        hasher.result(&mut buff);
        hasher.reset();

        hasher.input(&buff);
        hasher.result(&mut buff);

        self.bytes.append(&mut buff[0..4].to_vec());
    }
}

#[cfg(test)]
mod key_tests {
    use super::Key;
    use crate::key::constants::PRIVATE_KEY;

    #[test]
    fn test_constructor() {
        assert_eq!(Key::from_str("0").unwrap().bytes, vec![0x00]);
        assert_eq!(Key::from_str("00").unwrap().bytes, vec![0x00]);
        assert_eq!(
            Key::from_str("012345").unwrap().bytes,
            vec![0x01, 0x23, 0x45]
        )
    }

    #[test]
    fn should_throw_error_if_invalid_character() {
        assert_eq!(
            Key::from_str("0123456789abcdefg"),
            Err(hex::FromHexError::InvalidHexCharacter { c: 'g', index: 17 })
        )
    }

    #[test]
    fn should_return_bytes_encoded_as_hex_string() {
        let expected = PRIVATE_KEY.to_string();
        let actual = Key::from_str(PRIVATE_KEY).unwrap().as_hex_string();

        assert_eq!(expected, actual);
    }

    #[test]
    fn should_append_exactly_four_bytes() {
        let mut key = Key::from_str("01234").unwrap();
        let length = key.bytes.len();

        key.append_checksum();

        assert_eq!(length + 4, key.bytes.len())
    }

    #[test]
    fn should_append_expected_bytes_as_checksum() {
        let mut key = Key::from_str("344b160161c7b41a82fe8d6aebb55eaab753cb60").unwrap();
        key.append_checksum();
        let expected = "344b160161c7b41a82fe8d6aebb55eaab753cb60dabd0ca2";

        assert_eq!(key.as_hex_string(), expected);
    }
}
