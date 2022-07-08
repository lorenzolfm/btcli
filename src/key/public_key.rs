use crate::key::{Key, PrivateKey};
use secp256k1::{Secp256k1, SecretKey};

pub struct PublicKey {
    compressed: Key,
    uncompressed: Key,
}

impl PublicKey {
    fn from_private_key(pk: PrivateKey) -> Self {
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&pk.key.bytes).unwrap(),
        );

        PublicKey {
            compressed: Key { bytes: pubkey.serialize().to_vec() },
            uncompressed: Key { bytes: pubkey.serialize_uncompressed().to_vec() },
        }
    }

    fn get_address_from_compressed(self) -> String {
        let mut pkh = Key { bytes: self.compressed.hash160() };
        pkh.bytes.insert(0, 0x00);
        pkh.append_checksum();

        bs58::encode(&pkh.bytes).into_string()
    }

    fn get_address_from_uncompressed(self) -> String {
        let mut pkh = Key { bytes: self.uncompressed.hash160() };
        pkh.bytes.insert(0, 0x00);
        pkh.append_checksum();

        bs58::encode(&pkh.bytes).into_string()
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
            public_key.compressed.as_hex_string(),
            constants::COMPRESSED_PUBLIC_KEY,
        );
        assert_eq!(
            public_key.uncompressed.as_hex_string(),
            constants::UNCOMPRESSED_PUBLIC_KEY,
        )
    }

    #[test]
    fn should_return_expected_address_from_compressed() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.get_address_from_compressed(),
            "1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy",
        )
    }

    #[test]
    fn should_return_expected_address_from_uncompressed() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.get_address_from_uncompressed(),
            "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x",
        )

    }
}
