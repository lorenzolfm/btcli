use crate::key::{Key, PrivateKey, PrivateKeyError};
use secp256k1::{rand, Secp256k1, SecretKey};

type Coordinates = (String, String);

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    pub compressed: Vec<u8>,
    pub uncompressed: Vec<u8>,
}

impl PublicKey {
    pub fn from_private_key(pk: PrivateKey) -> Self {
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&pk.key).unwrap(),
        );

        PublicKey {
            compressed: pubkey.serialize().to_vec(),
            uncompressed: pubkey.serialize_uncompressed().to_vec(),
        }
    }

    pub fn from_private_key_string(pk: &str) -> Result<Self, PrivateKeyError> {
        let pk = PrivateKey::from_str(pk)?;

        Ok(PublicKey::from_private_key(pk))
    }

    pub fn get_address_from_compressed(self) -> String {
        let mut pkh = self.compressed.hash160();
        pkh.insert(0, 0x00);
        pkh.append_checksum();

        bs58::encode(&pkh).into_string()
    }

    pub fn get_address_from_uncompressed(self) -> String {
        let mut pkh = self.uncompressed.hash160();
        pkh.insert(0, 0x00);
        pkh.append_checksum();

        bs58::encode(&pkh).into_string()
    }

    pub fn get_coordinates(self) -> Coordinates {
        (
            hex::encode(&self.uncompressed[1..33]),
            hex::encode(&self.uncompressed[33..]),
        )
    }

    pub fn vanity_address(vanity: &str) -> String {
        loop {
            let secp = Secp256k1::new();

            let secret_key = SecretKey::new(&mut rand::thread_rng());

            let pubkey = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secret_key,
            );

            let pubkey = PublicKey {
                compressed: pubkey.serialize().to_vec(),
                uncompressed: pubkey.serialize().to_vec(),
            };

            let compressed_address = &pubkey.get_address_from_compressed();
            let prefix = &compressed_address.as_str()[1 .. vanity.len() + 1];

            if prefix == vanity {
                return compressed_address.to_string()
            }
        }
    }

    /// Returns a new address from an compressed public key, derived from a random secret key.
    pub fn get_new_address() -> String {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());

        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secret_key,
        );

        let pubkey = PublicKey {
            compressed: pubkey.serialize().to_vec(),
            uncompressed: pubkey.serialize().to_vec(),
        };

        pubkey.get_address_from_compressed()
    }
}

#[cfg(test)]
mod public_key_tests {
    use super::*;
    use crate::key::constants;

    #[test]
    fn should_return_expected_keys() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let mut public_key = PublicKey::from_private_key(pk);

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
    fn should_return_expected_keys_given_a_private_key_as_string() {
        let pk = PublicKey::from_private_key_string(
            constants::PRIVATE_KEY,
        ).unwrap();

        assert_eq!(
            pk.compressed,
            hex::decode(constants::COMPRESSED_PUBLIC_KEY).unwrap()
        );
        assert_eq!(
            pk.uncompressed,
            hex::decode(constants::UNCOMPRESSED_PUBLIC_KEY).unwrap()
        )
    }

    #[test]
    fn testing_for_error() {
        let r = PublicKey::from_private_key_string(
            constants::INVALID_PRIVATE_KEY
        );

        assert_eq!(r, Err(PrivateKeyError::GreaterThanCurveOrder))
    }

    #[test]
    fn should_return_expected_address_from_compressed() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.get_address_from_compressed(),
            constants::ADDRESS_FROM_COMPRESSED,
        )
    }

    #[test]
    fn should_return_expected_address_from_uncompressed() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.get_address_from_uncompressed(),
            constants::ADDRESS_FROM_UNCOMPRESSED,
        )

    }

    #[test]
    fn should_return_expected_coordinates_from_public_key() {
        let pk = PrivateKey::from_str(constants::PRIVATE_KEY).unwrap();
        let public_key = PublicKey::from_private_key(pk);

        assert_eq!(
            public_key.get_coordinates(),
            (
                "f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a".to_string(),
                "07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb".to_string(),
            )
        )
    }

    #[test]
    fn should_return_a_vanity_address() {
        let prefix = "Lo";
        let vanity_address = PublicKey::vanity_address(prefix);

        assert_eq!(&vanity_address[1..3], "Lo");
    }

    #[test]
    fn should_return_an_address() {
        let address = PublicKey::get_new_address();

        assert_eq!(&address[0..1], "1");
        assert!(address.len() >= 26);
        assert!(address.len() <= 36);
    }
}
