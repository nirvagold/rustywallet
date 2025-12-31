use anyhow::{anyhow, Result};
use colored::Colorize;
use rustywallet::signer::{bitcoin::sign_bitcoin_message, ethereum::sign_ethereum_message};

use crate::utils::parse_private_key;

pub fn run(key: &str, message: &str, format: &str) -> Result<()> {
    let private_key = parse_private_key(key)?;

    println!("{}", "Message Signing".bold());
    println!();
    println!("  {} \"{}\"", "Message:".bold(), message);
    println!("  {} {}", "Format:".bold(), format);
    println!();

    match format {
        "bitcoin" => {
            let signature = sign_bitcoin_message(&private_key, message)
                .map_err(|e| anyhow!("Signing failed: {}", e))?;
            println!("  {} {}", "Signature:".bold(), signature.green());
            println!();
            println!("  {} Base64 encoded (BIP-137 compatible)", "Note:".bold());
        }
        "ethereum" => {
            let signature = sign_ethereum_message(&private_key, message.as_bytes())
                .map_err(|e| anyhow!("Signing failed: {}", e))?;
            let sig_hex = signature.to_ethereum_hex();
            println!("  {} {}", "Signature:".bold(), sig_hex.green());
            println!();
            println!("  {} Hex encoded (EIP-191 personal_sign)", "Note:".bold());
        }
        "raw" => {
            // Sign raw message using Bitcoin format for simplicity
            let signature = sign_bitcoin_message(&private_key, message)
                .map_err(|e| anyhow!("Signing failed: {}", e))?;
            println!("  {} {}", "Signature:".bold(), signature.green());
            println!();
            println!("  {} Base64 encoded", "Note:".bold());
        }
        _ => return Err(anyhow!("Invalid format: {}", format)),
    }

    Ok(())
}
