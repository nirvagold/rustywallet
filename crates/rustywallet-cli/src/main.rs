use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;
mod utils;

#[derive(Parser)]
#[command(name = "rustywallet")]
#[command(version, about = "Cryptocurrency wallet CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a random private key
    Generate {
        /// Output format
        #[arg(short, long, default_value = "hex", value_parser = ["hex", "wif"])]
        format: String,

        /// Network for WIF format
        #[arg(short, long, default_value = "mainnet", value_parser = ["mainnet", "testnet"])]
        network: String,
    },

    /// Generate or validate mnemonic phrase
    Mnemonic {
        /// Word count for generation
        #[arg(short, long, default_value = "12", value_parser = ["12", "15", "18", "21", "24"])]
        words: String,

        /// Optional passphrase for seed derivation
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Validate existing mnemonic
        #[arg(short, long)]
        validate: Option<String>,

        /// Show seed hex
        #[arg(long)]
        show_seed: bool,
    },

    /// Derive address from key
    Address {
        /// Private key (hex or WIF)
        #[arg(short, long)]
        key: String,

        /// Address type
        #[arg(short = 't', long, default_value = "segwit", value_parser = ["legacy", "segwit", "taproot", "ethereum"])]
        r#type: String,

        /// Network
        #[arg(short, long, default_value = "mainnet", value_parser = ["mainnet", "testnet"])]
        network: String,
    },

    /// HD wallet derivation from mnemonic
    Hd {
        /// Mnemonic phrase
        #[arg(short, long)]
        mnemonic: String,

        /// Optional passphrase
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Derivation path
        #[arg(long, default_value = "m/44'/0'/0'/0/0")]
        path: String,

        /// Address type
        #[arg(short = 't', long, default_value = "segwit", value_parser = ["legacy", "segwit", "taproot", "ethereum"])]
        address_type: String,

        /// Network
        #[arg(short, long, default_value = "mainnet", value_parser = ["mainnet", "testnet"])]
        network: String,
    },

    /// Sign a message
    Sign {
        /// Private key (hex or WIF)
        #[arg(short, long)]
        key: String,

        /// Message to sign
        #[arg(short, long)]
        message: String,

        /// Signature format
        #[arg(short, long, default_value = "bitcoin", value_parser = ["bitcoin", "ethereum", "raw"])]
        format: String,
    },

    /// Verify a signature
    Verify {
        /// Address or public key
        #[arg(short, long)]
        address: String,

        /// Original message
        #[arg(short, long)]
        message: String,

        /// Signature to verify
        #[arg(short, long)]
        signature: String,

        /// Signature format
        #[arg(short, long, default_value = "bitcoin", value_parser = ["bitcoin", "ethereum"])]
        format: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Generate { format, network } => commands::generate::run(&format, &network),
        Commands::Mnemonic {
            words,
            passphrase,
            validate,
            show_seed,
        } => commands::mnemonic::run(&words, passphrase.as_deref(), validate.as_deref(), show_seed),
        Commands::Address { key, r#type, network } => {
            commands::address::run(&key, &r#type, &network)
        }
        Commands::Hd {
            mnemonic,
            passphrase,
            path,
            address_type,
            network,
        } => commands::hd::run(&mnemonic, passphrase.as_deref(), &path, &address_type, &network),
        Commands::Sign {
            key,
            message,
            format,
        } => commands::sign::run(&key, &message, &format),
        Commands::Verify {
            address,
            message,
            signature,
            format,
        } => commands::verify::run(&address, &message, &signature, &format),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
