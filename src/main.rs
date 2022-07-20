use btcli::key::Key;
use btcli::key::{PrivateKey, PublicKey};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a new address from a compressed public key derived from a random secret key
    GenerateNewAddress,

    /// Get the byte array representation of a private key
    #[clap(arg_required_else_help = true)]
    PrivateKeyToByteArray {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Get the 'compressed' private key
    #[clap(arg_required_else_help = true)]
    CompressedPrivateKey {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Get the private key in the WIF format
    #[clap(arg_required_else_help = true)]
    PrivateKeyToWif {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Get the private key in the WIF compressed format
    PrivateKeyToCompressedWif {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Converts the private key to decimals
    PrivateKeyToDecimals {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Logs the compressed public key and the uncompressed public key given a private key
    PubKeyFromPrivate {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Logs the public key coordinates given a private key
    GetPubKeyCoords {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Logs the address generated from the compressed public key
    GetAddressFromCompressed {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Logs the address generate from the uncompressed public key
    GetAddressFromUncompressed {
        /// The private key as a hexadecimal string
        #[clap(value_parser)]
        private_key: String,
    },

    /// Generates a vanity address given a prefix
    GenVanityAddress {
        /// The prefix wanted
        #[clap(value_parser)]
        prefix: String,
    }
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::GenerateNewAddress => {
            println!("{}", PublicKey::get_new_address());
        }
        Commands::PrivateKeyToByteArray { private_key } => {
            println!("{:?}", PrivateKey::from_str(&private_key).unwrap().key)
        }
        Commands::CompressedPrivateKey { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();

            println!("{}", priv_key.as_hex_compressed_string())
        }
        Commands::PrivateKeyToWif { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();

            println!("{}", priv_key.as_wif());
        }
        Commands::PrivateKeyToCompressedWif { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();

            println!("{}", priv_key.as_wif_compressed());
        }
        Commands::PrivateKeyToDecimals { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();

            println!("{}", priv_key.as_decimals());
        },
        Commands::PubKeyFromPrivate { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();
            let mut pub_key = PublicKey::from_private_key(priv_key);

            println!("Compressed key {}", pub_key.compressed.as_hex_string());
            println!("Uncompressed key {}", pub_key.uncompressed.as_hex_string());
        }
        Commands::GetPubKeyCoords { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();
            let pub_key = PublicKey::from_private_key(priv_key);

            let (x, y) = pub_key.get_coordinates();

            println!("x = {}, y = {}", x, y);
        }
        Commands::GetAddressFromCompressed { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();
            let pub_key = PublicKey::from_private_key(priv_key);

            println!("{}", pub_key.get_address_from_compressed())
        }
        Commands::GetAddressFromUncompressed { private_key } => {
            let priv_key = PrivateKey::from_str(&private_key).unwrap();
            let pub_key = PublicKey::from_private_key(priv_key);

            println!("{}", pub_key.get_address_from_uncompressed())
        }
        Commands::GenVanityAddress { prefix } => {
            let vanity_address = PublicKey::vanity_address(&prefix);

            println!("{}", vanity_address);
        }
    }
}
