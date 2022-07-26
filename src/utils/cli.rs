use crate::key::PublicKey;
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
