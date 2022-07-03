use crate::utils::ToByteArray;

#[derive(Debug, PartialEq)]
pub struct Key {
    bytes: Vec<u8>,
}

impl Key {
    fn new(key_as_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = key_as_str.to_string().to_byte_array()?;

        Ok(Key { bytes })
    }
}

#[cfg(test)]
mod key_tests {
    use super::Key;

    #[test]
    fn test_constructor() {
        assert_eq!(Key::new("0").unwrap().bytes, vec![0x00]);
        assert_eq!(Key::new("00").unwrap().bytes, vec![0x00]);
        assert_eq!(Key::new("012345").unwrap().bytes, vec![0x01, 0x23, 0x45])
    }

    #[test]
    fn should_throw_error_if_invalid_character() {
        assert_eq!(
            Key::new("0123456789abcdefg"),
            Err(hex::FromHexError::InvalidHexCharacter { c: 'g', index: 17 })
        )
    }
}
