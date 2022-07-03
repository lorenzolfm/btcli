pub trait ToByteArray {
    fn to_byte_array(self) -> Vec<u8>;
}

impl ToByteArray for String {
    fn to_byte_array(self) -> Vec<u8> {
        match self.len() % 2 == 0 {
            true => hex::decode(self).unwrap(),
            false => hex::decode(
                format!("{:0>width$}", self, width = self.len() + 1)
            ).unwrap()
        }
    }
}

#[cfg(test)]
mod to_byte_array_tests {
    use super::ToByteArray;

    fn assert_eq(input: &str, expected: Vec<u8>) {
        assert_eq!(
            input.to_string().to_byte_array(),
            expected,
        )
    }

    #[test]
    fn should_return_expected_byte_array() {
        assert_eq("00", vec![0x00]);
        assert_eq("05", vec![0x05]);
        assert_eq("6f", vec![0x6f]);
        assert_eq("80", vec![0x80]);
        assert_eq("0142", vec![0x01, 0x42]);
        assert_eq("0488b21e", vec![0x04, 0x88, 0xb2, 0x1e]);
    }

    #[test]
    fn should_return_array_half_as_long_as_the_string_input() {
        let input = "0123456789".to_string();
        let expected = input.len() / 2;

        assert_eq!(input.to_byte_array().len(), expected)
    }

    #[test]
    fn should_insert_padding_if_input_is_odd() {
        let input = "012".to_string();

        assert_eq!(input.to_byte_array(), vec![0x00, 0x12])
    }

}
