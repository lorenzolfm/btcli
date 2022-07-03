pub use crate::utils::ToByteArray;

pub struct Key {
    bytes: Vec<u8>
}

impl Key {
    fn new(key_as_str: &str) -> Self {
        Key {
            bytes: key_as_str
                    .to_string()
                    .to_byte_array()
        }
    }
}

#[cfg(test)]
mod key_tests {
    use super::Key;

    #[test]
    fn test_constructor() {
        assert_eq!(Key::new("00").bytes, vec![0x00]);
        assert_eq!(Key::new("012345").bytes, vec![0x01, 0x23, 0x45])
    }
}
