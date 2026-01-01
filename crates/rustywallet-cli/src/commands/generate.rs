use anyhow::Result;
use colored::Colorize;
use rustywallet::keys::private_key::PrivateKey;

use crate::utils::parse_key_network;

pub fn run(format: &str, network: &str) -> Result<()> {
    let key = PrivateKey::random();

    println!("{}", "Generated Private Key".bold());
    println!();

    match format {
        "hex" => {
            let hex = key.to_hex();
            println!("  {} {}", "Hex:".bold(), hex.yellow());
        }
        "wif" => {
            let net = parse_key_network(network)?;
            let wif = key.to_wif(net);
            println!("  {} {}", "WIF:".bold(), wif.yellow());
            println!("  {} {}", "Network:".bold(), network);
        }
        _ => unreachable!(),
    }

    // Also show public key
    let pubkey = key.public_key();
    println!();
    println!(
        "  {} {}",
        "Public Key:".bold(),
        hex::encode(pubkey.to_compressed()).green()
    );

    println!();
    println!(
        "{}",
        "⚠️  Keep your private key safe! Never share it.".yellow()
    );

    Ok(())
}
