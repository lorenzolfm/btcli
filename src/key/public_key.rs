use crate::key::{Key, PrivateKey};
use secp256k1::{Secp256k1, SecretKey};

pub struct PublicKey {
    compressed_key: Key,
    uncompressed_key: Key,
}

impl PublicKey {
    fn from_private_key(pk: PrivateKey) -> Self {
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&pk.key.bytes).unwrap(),
        );

        

        PublicKey {
            compressed_key: Key { bytes: pubkey.serialize().to_vec() },
            uncompressed_key: Key { bytes: pubkey.serialize_uncompressed().to_vec() },
        }
    }
}

#[cfg(test)]
mod public_key_tests {
    use super::*;
    use crate::key::constants;

    #[test]
    fn should_return_expected_keys() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.compressed_key.as_hex_string(),
            constants::COMPRESSED_PUBLIC_KEY,
        );
        assert_eq!(
            public_key.uncompressed_key.as_hex_string(),
            constants::UNCOMPRESSED_PUBLIC_KEY,
        )
    }
}
