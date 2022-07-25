use crate::key::PublicKey;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Debug, Subcommand)]
enum  Commands {
    /// Logs the address derived from a given private key
    GetAddressFrom {
        #[clap(value_parser)]
        private_key: String,
    }
}

pub fn run() {
    let cli = Cli::parse();

    match cli.commands {
        Commands::GetAddressFrom { private_key } => {
            let pub_key = PublicKey::from_private_key_string(&private_key);

            println!("{}", pub_key.get_address_from_compressed());
        }
    }
}
