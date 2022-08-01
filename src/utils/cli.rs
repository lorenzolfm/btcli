use crate::key::{PublicKey, PrivateKey};
use crate::base58decoder::base58decode;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Logs the address derived from a compressed public key, given private key.
    GetCompressedAddressFrom(PrivKeyArg),

    /// Logs the address derived from a uncompressed public key, given the private key.
    GetUncompressedAddressFrom(PrivKeyArg),

    /// Logs the public key coordinates, given the private key.
    GetCoordinatesFrom(PrivKeyArg),

    /// Generates and logs an address from a random private key.
    GetAddress,

    /// Computes a vanity address given the desired prefix.
    GetVanity {
        #[clap(value_parser)]
        prefix: String,
    },

    /// Logs the compressed private key as a hex string
    GetHexCompressed(PrivKeyArg),

    /// Logs the private key using the "Wallet Import Format".
    GetWif(PrivKeyArg),

    /// Logs the private key using the "Compressed Wallet Import Format"
    GetWifCompressed(PrivKeyArg),

    /// Decodes and logs the provided input
    Base58Decode {
        #[clap(value_parser)]
        encoded: String,
    }
}

#[derive(Debug, Args)]
struct PrivKeyArg {
    #[clap(value_parser)]
    private_key: String,
}

pub fn run() {
    let cli = Cli::parse();

    match cli.commands {
        Commands::GetCompressedAddressFrom(arg) => log_compressed_address(&arg.private_key),
        Commands::GetUncompressedAddressFrom(arg) => log_uncompressed_address(&arg.private_key),
        Commands::GetCoordinatesFrom(arg) => log_coordinates(&arg.private_key),
        Commands::GetAddress => println!("{}", PublicKey::get_new_address()),
        Commands::GetVanity { prefix } => println!("{}", PublicKey::vanity_address(&prefix)),

        Commands::GetHexCompressed(arg) => log_hex_compressed_private_key(&arg.private_key),
        Commands::GetWif(arg) => log_wif_format(&arg.private_key),
        Commands::GetWifCompressed(arg) => log_wif_compressed_format(&arg.private_key),

        Commands::Base58Decode { encoded } => log_base58_decoded(&encoded)
    }
}

fn log_compressed_address(private_key: &str) {
    let k = PublicKey::from_private_key_string(&private_key);

    match k {
        Ok(pubkey) => println!("{}", pubkey.get_address_from_compressed()),
        Err(error) => eprintln!("Error getting address from private key string: {:?}", error),
    }
}

fn log_uncompressed_address(private_key: &str) {
    let k = PublicKey::from_private_key_string(&private_key);

    match k {
        Ok(pubkey) => println!("{}", pubkey.get_address_from_uncompressed()),
        Err(error) => eprintln!("Error getting address from private key string: {:?}", error),
    }
}

fn log_coordinates(private_key: &str) {
    let k = PublicKey::from_private_key_string(&private_key);

    match k {
        Ok(pubkey) => {
            let (x, y) = pubkey.get_coordinates();

            println!("x = {}", x);
            println!("y = {}", y);
        }
        Err(error) => eprintln!("Error getting address from private key string: {:?}", error),
    }
}

fn log_hex_compressed_private_key(private_key: &str) {
    let r = PrivateKey::from_str(private_key);

    match r {
        Ok(privkey) => println!("Compressed public key: {}", privkey.as_hex_compressed_string()),
        Err(error) => eprintln!("Error converting input to private key: {:?}", error),
    }
}

fn log_wif_format(private_key: &str) {
    let r = PrivateKey::from_str(private_key);

    match r {
        Ok(privkey) => println!("WIF: {}", privkey.as_wif()),
        Err(error) => eprintln!("Error converting input to private key: {:?}", error),
    }
}

fn log_wif_compressed_format(private_key: &str) {
    let r = PrivateKey::from_str(private_key);

    match r {
        Ok(privkey) => println!("WIF compressed: {}", privkey.as_wif_compressed()),
        Err(error) => eprintln!("Error converting input to private key: {:?}", error),
    }
}

fn log_base58_decoded(encoded: &str) {
    let r = base58decode(encoded);

    match r {
        Ok(decoded) => {
            println!("Version: {}", decoded.0);
            println!("Payload: {}", decoded.1);
            println!("Checksum: {}", decoded.2);
        },
        Err(error) => {
            eprintln!("Error decoding input: {:?}", error);
        }
    }
}
