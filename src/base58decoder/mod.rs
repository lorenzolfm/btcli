/// Represents a decoded base58check string
///
/// The first value is the version;
/// The second value is the payload;
/// The third value is the checksum;
type Decoded = (String, String, String);

/// Decodes a base58check encoded string slice
///
/// # Arguments
///
/// * `input`: A base58check enconded string slice
///
/// # Return
///
/// * A `Decoded` type
pub fn base58decode(input: &str) -> Result<Decoded, bs58::decode::Error> {
    let decoded = bs58::decode(input).into_vec()?;

    let version = hex::encode(vec![decoded[0]]);
    let payload = hex::encode(&decoded[1..decoded.len() - 4]);
    let checksum = hex::encode(&decoded[decoded.len() - 4..decoded.len()]);

    Ok((version, payload, checksum))
}

#[cfg(test)]
mod base58decoder_tests {
    use super::base58decode;

    #[test]
    fn test_with_wif_private_key_format() {
        let (version, payload, checksum) =
            base58decode("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn").unwrap();

        assert_eq!(version, "80");
        assert_eq!(
            payload,
            "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"
        );
        assert_eq!(checksum, "c47e83ff");
    }

    #[test]
    fn test_with_wif_compressed_private_key_format() {
        let (version, payload, checksum) =
            base58decode("KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ").unwrap();

        assert_eq!(version, "80");
        assert_eq!(
            payload,
            "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd01"
        );
        assert_eq!(checksum, "7695738b");
    }

    #[test]
    fn should_throw_error_if_invalid_base58_char() {
        assert_eq!(
            base58decode("KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtl"),
            Err(bs58::decode::Error::InvalidCharacter { character: 'l', index: 51 }),
        )
    }
}
