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
